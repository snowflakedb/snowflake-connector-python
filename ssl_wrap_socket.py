# -*- coding: utf-8 -*-
#
# SSL wrap socket for PyOpenSSL.
# Mostly copied from
#
# https://github.com/shazow/urllib3/blob/master/urllib3/contrib/pyopenssl.py
#
# and added OCSP validator on the top.
#

"""
Insecure mode flag. OCSP validation will be skipped if True
"""
FEATURE_INSECURE_MODE = False

"""
OCSP Response cache file name
"""
FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = None

import logging
import ssl
import sys
from socket import error as SocketError
from socket import (socket, timeout)

import OpenSSL.SSL
from botocore.vendored.requests.packages.urllib3 import connection \
    as urllib3_connection
from botocore.vendored.requests.packages.urllib3 import util \
    as urllib3_util
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.backends.openssl.x509 import _Certificate

from .errorcode import (ER_SERVER_CERTIFICATE_REVOKED)
from .errors import (OperationalError)
from .proxy import (set_proxies, PROXY_HOST, PROXY_PORT, PROXY_USER,
                    PROXY_PASSWORD)
from .ssl_wrap_util import wait_for_read, wait_for_write
from .compat import PY2

try:  # Platform-specific: Python 2
    from socket import _fileobject
except ImportError:  # Platform-specific: Python 3
    _fileobject = None
    from .backport_makefile import backport_makefile

# Map from urllib3 to PyOpenSSL compatible parameter-values.
_openssl_versions = {
    ssl.PROTOCOL_SSLv23: OpenSSL.SSL.SSLv23_METHOD,
    ssl.PROTOCOL_TLSv1: OpenSSL.SSL.TLSv1_METHOD,
}
if hasattr(ssl, 'PROTOCOL_TLSv1_1') and hasattr(OpenSSL.SSL, 'TLSv1_1_METHOD'):
    _openssl_versions[ssl.PROTOCOL_TLSv1_1] = OpenSSL.SSL.TLSv1_1_METHOD

if hasattr(ssl, 'PROTOCOL_TLSv1_2') and hasattr(OpenSSL.SSL, 'TLSv1_2_METHOD'):
    _openssl_versions[ssl.PROTOCOL_TLSv1_2] = OpenSSL.SSL.TLSv1_2_METHOD

try:
    _openssl_versions.update({ssl.PROTOCOL_SSLv3: OpenSSL.SSL.SSLv3_METHOD})
except AttributeError:
    pass

_stdlib_to_openssl_verify = {
    ssl.CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
    ssl.CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
    ssl.CERT_REQUIRED:
        OpenSSL.SSL.VERIFY_PEER + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
}
_openssl_to_stdlib_verify = dict(
    (v, k) for k, v in _stdlib_to_openssl_verify.items()
)

# OpenSSL will only write 16K at a time
SSL_WRITE_BLOCKSIZE = 16384

log = logging.getLogger(__name__)


def inject_into_urllib3():
    """
    Monkey-patch urllib3 with PyOpenSSL-backed SSL-support and OCSP.
    """
    log.debug(u'Injecting ssl_wrap_socket_with_ocsp')
    urllib3_connection.ssl_wrap_socket = ssl_wrap_socket_with_ocsp


def _dnsname_to_stdlib(name):
    """
    Converts a dNSName SubjectAlternativeName field to the form used by the
    standard library on the given Python version.

    Cryptography produces a dNSName as a unicode string that was idna-decoded
    from ASCII bytes. We need to idna-encode that string to get it back, and
    then on Python 3 we also need to convert to unicode via UTF-8 (the stdlib
    uses PyUnicode_FromStringAndSize on it, which decodes via UTF-8).
    """

    def idna_encode(name):
        """
        Borrowed wholesale from the Python Cryptography Project. It turns out
        that we can't just safely call `idna.encode`: it can explode for
        wildcard names. This avoids that problem.
        """
        import idna

        for prefix in [u'*.', u'.']:
            if name.startswith(prefix):
                name = name[len(prefix):]
                return prefix.encode('ascii') + idna.encode(name)
        return idna.encode(name)

    name = idna_encode(name)
    if sys.version_info >= (3, 0):
        name = name.decode('utf-8')
    return name


def get_subj_alt_name(peer_cert):
    """
    Given an PyOpenSSL certificate, provides all the subject alternative names.
    """
    # Pass the cert to cryptography, which has much better APIs for this.
    if hasattr(peer_cert, "to_cryptography"):
        cert = peer_cert.to_cryptography()
    else:
        # This is technically using private APIs, but should work across all
        # relevant versions before PyOpenSSL got a proper API for this.
        cert = _Certificate(openssl_backend, peer_cert._x509)

    # We want to find the SAN extension. Ask Cryptography to locate it (it's
    # faster than looping in Python)
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        # No such extension, return the empty list.
        return []
    except (x509.DuplicateExtension, x509.UnsupportedExtension,
            x509.UnsupportedGeneralNameType, UnicodeError) as e:
        # A problem has been found with the quality of the certificate. Assume
        # no SAN field is present.
        log.warning(
            "A problem was encountered with the certificate that prevented "
            "urllib3 from finding the SubjectAlternativeName field. This can "
            "affect certificate validation. The error was %s",
            e,
        )
        return []

    # We want to return dNSName and iPAddress fields. We need to cast the IPs
    # back to strings because the match_hostname function wants them as
    # strings.
    # Sadly the DNS names need to be idna encoded and then, on Python 3, UTF-8
    # decoded. This is pretty frustrating, but that's what the standard library
    # does with certificates, and so we need to attempt to do the same.
    names = [
        ('DNS', _dnsname_to_stdlib(name))
        for name in ext.get_values_for_type(x509.DNSName)
    ]
    names.extend(
        ('IP Address', str(name))
        for name in ext.get_values_for_type(x509.IPAddress)
    )

    return names


class WrappedSocket(object):
    '''API-compatibility wrapper for Python OpenSSL's Connection-class.

    Note: _makefile_refs, _drop() and _reuse() are needed for the garbage
    collector of pypy.
    '''

    def __init__(self, connection, socket, suppress_ragged_eofs=True):
        self.connection = connection
        self.socket = socket
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._makefile_refs = 0
        self._closed = False

    def fileno(self):
        return self.socket.fileno()

    # Copy-pasted from Python 3.5 source code
    def _decref_socketios(self):
        if self._makefile_refs > 0:
            self._makefile_refs -= 1
        if self._closed:
            self.close()

    def recv(self, *args, **kwargs):
        try:
            data = self.connection.recv(*args, **kwargs)
        except OpenSSL.SSL.SysCallError as e:
            if self.suppress_ragged_eofs and e.args == (-1, 'Unexpected EOF'):
                return b''
            else:
                raise SocketError(str(e))
        except OpenSSL.SSL.ZeroReturnError as e:
            if self.connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return b''
            else:
                raise
        except OpenSSL.SSL.WantReadError:
            rd = wait_for_read(self.socket, self.socket.gettimeout())
            if not rd:
                raise timeout('The read operation timed out')
            else:
                return self.recv(*args, **kwargs)
        else:
            return data

    def recv_into(self, *args, **kwargs):
        try:
            return self.connection.recv_into(*args, **kwargs)
        except OpenSSL.SSL.SysCallError as e:
            if self.suppress_ragged_eofs and e.args == (-1, 'Unexpected EOF'):
                return 0
            else:
                raise SocketError(str(e))
        except OpenSSL.SSL.ZeroReturnError as e:
            if self.connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return 0
            else:
                raise
        except OpenSSL.SSL.WantReadError:
            rd = wait_for_read(self.socket, self.socket.gettimeout())
            if not rd:
                raise timeout('The read operation timed out')
            else:
                return self.recv_into(*args, **kwargs)

    def settimeout(self, timeout):
        return self.socket.settimeout(timeout)

    def _send_until_done(self, data):
        while True:
            try:
                return self.connection.send(data)
            except OpenSSL.SSL.WantWriteError:
                wr = wait_for_write(self.socket, self.socket.gettimeout())
                if not wr:
                    raise timeout()
                continue
            except OpenSSL.SSL.SysCallError as e:
                raise SocketError(str(e))

    def sendall(self, data):
        total_sent = 0
        while total_sent < len(data):
            sent = self._send_until_done(
                data[total_sent:total_sent + SSL_WRITE_BLOCKSIZE])
            total_sent += sent

    def shutdown(self):
        # FIXME rethrow compatible exceptions should we ever use this
        self.connection.shutdown()

    def close(self):
        if self._makefile_refs < 1:
            try:
                self._closed = True
                return self.connection.close()
            except OpenSSL.SSL.Error:
                return
        else:
            self._makefile_refs -= 1

    def getpeercert(self, binary_form=False):
        x509 = self.connection.get_peer_certificate()

        if not x509:
            return x509

        if binary_form:
            return OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_ASN1,
                x509)

        return {
            'subject': (
                (('commonName', x509.get_subject().CN),),
            ),
            'subjectAltName': get_subj_alt_name(x509)
        }

    def _reuse(self):
        self._makefile_refs += 1

    def _drop(self):
        if self._makefile_refs < 1:
            self.close()
        else:
            self._makefile_refs -= 1


if _fileobject:  # Platform-specific: Python 2
    def makefile(self, mode, bufsize=-1):
        self._makefile_refs += 1
        return _fileobject(self, mode, bufsize, close=True)
else:  # Platform-specific: Python 3
    makefile = backport_makefile

WrappedSocket.makefile = makefile

DEFAULT_SSL_CIPHER_LIST = urllib3_util.ssl_.DEFAULT_CIPHERS
if isinstance(DEFAULT_SSL_CIPHER_LIST, str):
    DEFAULT_SSL_CIPHER_LIST = DEFAULT_SSL_CIPHER_LIST.encode('utf-8')


def ssl_wrap_socket(
        sock, keyfile=None, certfile=None, cert_reqs=None,
        ca_certs=None, server_hostname=None, ssl_version=None):
    ctx = OpenSSL.SSL.Context(_openssl_versions[ssl_version])
    if certfile:
        # Match behaviour of the normal python ssl library
        keyfile = keyfile or certfile
        ctx.use_certificate_file(certfile)
    if keyfile:
        ctx.use_privatekey_file(keyfile)
    if cert_reqs != ssl.CERT_NONE:
        ctx.set_verify(_stdlib_to_openssl_verify[cert_reqs], _verify_callback)
    if ca_certs:
        try:
            ctx.load_verify_locations(ca_certs, None)
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError('bad ca_certs: %r' % ca_certs, e)
    else:
        ctx.set_default_verify_paths()

    # Disable TLS compression to mitigate CRIME attack (issue #309)
    OP_NO_COMPRESSION = 0x20000
    ctx.set_options(OP_NO_COMPRESSION)

    # Set list of supported ciphersuites.
    ctx.set_cipher_list(DEFAULT_SSL_CIPHER_LIST)

    cnx = OpenSSL.SSL.Connection(ctx, sock)
    cnx.set_tlsext_host_name(server_hostname.encode(u'utf-8'))
    cnx.set_connect_state()

    while True:
        try:
            cnx.do_handshake()
        except OpenSSL.SSL.WantReadError:
            rd = wait_for_read(sock, sock.gettimeout())
            if not rd:
                raise timeout('select timed out')
            continue
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError('bad handshake: %r' % e)
        break

    return WrappedSocket(cnx, sock)


def _verify_callback(cnx, x509, err_no, err_depth, return_code):
    # NOTE: this cannot be used to verify certificate revocation status.
    # because get_cert_peer_chain returns None for some reason.
    return err_no == 0


def ssl_wrap_socket_with_ocsp(
        sock, keyfile=None, certfile=None, cert_reqs=None,
        ca_certs=None, server_hostname=None, ssl_version=None):
    ret = ssl_wrap_socket(
        sock, keyfile=keyfile, certfile=certfile, cert_reqs=cert_reqs,
        ca_certs=ca_certs, server_hostname=server_hostname,
        ssl_version=ssl_version)
    global FEATURE_INSECURE_MODE
    global FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME

    if PY2:
        # Python 2 uses pyasn1 for workaround. For some reason, asn1crypto
        # fails to parse OCSP response in Python 2.
        from .ocsp_pyasn1 import SnowflakeOCSP
    else:
        from .ocsp_asn1crypto import SnowflakeOCSP

    log.debug(u'insecure_mode: %s, '
              u'OCSP response cache file name: %s, '
              u'PROXY_HOST: %s, PROXY_PORT: %s, PROXY_USER: %s '
              u'PROXY_PASSWORD: %s',
              FEATURE_INSECURE_MODE,
              FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
              PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASSWORD)
    if not FEATURE_INSECURE_MODE:
        v = SnowflakeOCSP(
            proxies=set_proxies(
                PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASSWORD),
            ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
        ).validate(server_hostname, ret.connection)
        if not v:
            raise OperationalError(
                msg=(
                    u'The certificate is revoked or '
                    u'could not be validated: hostname={0}'.format(
                        server_hostname)),
                errno=ER_SERVER_CERTIFICATE_REVOKED)
    else:
        log.info(u'THIS CONNECTION IS IN INSECURE '
                 u'MODE. IT MEANS THE CERTIFICATE WILL BE '
                 u'VALIDATED BUT THE CERTIFICATE REVOCATION '
                 u'STATUS WILL NOT BE CHECKED.')

    return ret


def _openssl_connect(hostname, port=443):
    """
    OpenSSL connection without validating certificates. This is used to diagnose
    SSL issues.
    """
    client = socket()
    client.connect((hostname, port))
    client_ssl = OpenSSL.SSL.Connection(
        OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD), client)
    client_ssl.set_connect_state()
    client_ssl.set_tlsext_host_name(hostname.encode('utf-8'))
    client_ssl.do_handshake()
    return client_ssl
