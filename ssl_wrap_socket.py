# -*- coding: utf-8 -*-
#
# SSL wrap socket for PyOpenSSL.
# Mostly copied from 
#
# https://github.com/kennethreitz/requests/blob/master/requests/packages/urllib3/contrib/pyopenssl.py
#
# and added OCSP validator on the top.
#

"""
Insecure mode flag. OCSP validation will be skipped if True
"""
FEATURE_INSECURE_MODE = False

"""
OCSP Reponse cache file name
"""
FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = None

"""
Proxy, shared across all connections
"""
PROXY_HOST = None
PROXY_PORT = None
PROXY_USER = None
PROXY_PASSWORD = None
PREFIX_HTTP = 'http://'
PREFIX_HTTPS = 'https://'


def set_proxies(proxy_host, proxy_port, proxy_user=None, proxy_password=None):
    """
    Set proxy dict for requests
    """
    proxies = None
    if proxy_host and proxy_port:
        if proxy_host.startswith(PREFIX_HTTP):
            proxy_host = proxy_host[len(PREFIX_HTTP):]
        elif proxy_host.startswith(PREFIX_HTTPS):
            proxy_host = proxy_host[len(PREFIX_HTTPS):]
        if proxy_user or proxy_password:
            proxy_auth = u'{proxy_user}:{proxy_password}@'.format(
                proxy_user=proxy_user if proxy_user is not None else '',
                proxy_password=proxy_password if proxy_password is not
                                                 None else ''
            )
        else:
            proxy_auth = u''
        proxies = {
            u'http': u'http://{proxy_auth}{proxy_host}:{proxy_port}'.format(
                proxy_host=proxy_host,
                proxy_port=TO_UNICODE(proxy_port),
                proxy_auth=proxy_auth,
            ),
            u'https': u'http://{proxy_auth}{proxy_host}:{proxy_port}'.format(
                proxy_host=proxy_host,
                proxy_port=TO_UNICODE(proxy_port),
                proxy_auth=proxy_auth,
            ),
        }
    return proxies


# imports
import select
import socket
import ssl
import sys
from logging import getLogger
from socket import error as SocketError

import botocore.endpoint

# Monkey patch for all connections for AWS API. This is mainly for PUT
# and GET commands
original_get_proxies = botocore.endpoint.EndpointCreator._get_proxies


def _get_proxies(self, url):
    return set_proxies(
        PROXY_HOST,
        PROXY_PORT,
        PROXY_USER,
        PROXY_PASSWORD) or original_get_proxies(self, url)


botocore.endpoint.EndpointCreator._get_proxies = _get_proxies

import OpenSSL
import idna
from botocore.vendored.requests.packages.urllib3 import connection \
    as urllib3_connection
from botocore.vendored.requests.packages.urllib3 import util \
    as urllib3_util
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.backends.openssl.x509 import _Certificate

from .compat import (TO_UNICODE)
from .errorcode import (ER_SERVER_CERTIFICATE_REVOKED)
from .errors import (OperationalError)
from .ocsp_pyopenssl import SnowflakeOCSP

MAX = 64

# OpenSSL will only write 16K at a time
SSL_WRITE_BLOCKSIZE = 16384

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

_openssl_verify = {
    ssl.CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
    ssl.CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
    ssl.CERT_REQUIRED: OpenSSL.SSL.VERIFY_PEER
                       + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
}


def _verify_callback(cnx, x509, err_no, err_depth, return_code):
    return err_no == 0


DEFAULT_SSL_CIPHER_LIST = urllib3_util.ssl_.DEFAULT_CIPHERS


def get_subj_alt_name(peer_cert):
    """
    Given an PyOpenSSL certificate, provides all the subject alternative names.
    """
    # Pass the cert to cryptography, which has much better APIs for this.
    # This is technically using private APIs, but should work across all
    # relevant versions until PyOpenSSL gets something proper for this.
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
        logger = getLogger(__name__)
        logger.warning(
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
        for prefix in [u'*.', u'.']:
            if name.startswith(prefix):
                name = name[len(prefix):]
                return prefix.encode('ascii') + idna.encode(name)
        return idna.encode(name)

    name = idna_encode(name)
    if sys.version_info >= (3, 0):
        name = name.decode('utf-8')
    return name


class error(Exception):
    """ Base class for I/O related errors. """

    def __init__(self, *args, **kwargs):  # real signature unknown
        pass

    @staticmethod  # known case of __new__
    def __new__(*args, **kwargs):  # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    def __reduce__(self, *args, **kwargs):  # real signature unknown
        pass

    def __str__(self, *args, **kwargs):  # real signature unknown
        """ Return str(self). """
        pass

    characters_written = property(lambda self: object(), lambda self, v: None,
                                  lambda self: None)  # default

    errno = property(lambda self: object(), lambda self, v: None,
                     lambda self: None)  # default
    """POSIX exception code"""

    filename = property(lambda self: object(), lambda self, v: None,
                        lambda self: None)  # default
    """exception filename"""

    filename2 = property(lambda self: object(), lambda self, v: None,
                         lambda self: None)  # default
    """second exception filename"""

    strerror = property(lambda self: object(), lambda self, v: None,
                        lambda self: None)  # default
    """exception strerror"""


import errno

EBADF = getattr(errno, 'EBADF', 9)
EINTR = getattr(errno, 'EINTR', 4)

# -*- coding: utf-8 -*-
"""
backports.makefile
~~~~~~~~~~~~~~~~~~

Backports the Python 3 ``socket.makefile`` method for use with anything that
wants to create a "fake" socket object.
"""

try:  # Platform-specific: Python 2
    from socket import _fileobject
except:
    _fileobject = None
    from .backport_makefile import backport_makefile


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
            rd, wd, ed = select.select(
                [self.socket], [], [], self.socket.gettimeout())
            if not rd:
                raise socket.timeout('The read operation timed out')
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
            rd, wd, ed = select.select(
                [self.socket], [], [], self.socket.gettimeout())
            if not rd:
                raise socket.timeout('The read operation timed out')
            else:
                return self.recv_into(*args, **kwargs)

    def settimeout(self, timeout):
        return self.socket.settimeout(timeout)

    def _send_until_done(self, data):
        while True:
            try:
                return self.connection.send(data)
            except OpenSSL.SSL.WantWriteError:
                _, wlist, _ = select.select([], [self.socket], [],
                                            self.socket.gettimeout())
                if not wlist:
                    raise socket.timeout()
                continue

    def sendall(self, data):
        total_sent = 0
        while total_sent < len(data):
            sent = self._send_until_done(
                data[total_sent:total_sent + SSL_WRITE_BLOCKSIZE])
            total_sent += sent

    def shutdown(self):
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


if _fileobject:
    def makefile(self, mode, bufsize=-1):
        self._makefile_refs += 1
        return _fileobject(self, mode, bufsize, close=True)
else:  # Platform-specific: Python 3
    makefile = backport_makefile

WrappedSocket.makefile = makefile


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
        ctx.set_verify(_openssl_verify[cert_reqs], _verify_callback)
    if ca_certs:
        try:
            ctx.load_verify_locations(ca_certs, None)
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError('bad ca_certs: %r' % ca_certs, e)
    else:
        ctx.set_default_verify_paths()

    # Disable TLS compression to migitate CRIME attack (issue #309)
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
            rd, _, _ = select.select([sock], [], [], sock.gettimeout())
            if not rd:
                raise socket.timeout('select timed out')
            continue
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError('bad handshake', e)
        break

    return WrappedSocket(cnx, sock)


def ssl_wrap_socket_with_ocsp(
        sock, keyfile=None, certfile=None, cert_reqs=None,
        ca_certs=None, server_hostname=None, ssl_version=None):
    ret = ssl_wrap_socket(
        sock, keyfile=keyfile, certfile=certfile, cert_reqs=cert_reqs,
        ca_certs=ca_certs, server_hostname=server_hostname,
        ssl_version=ssl_version)
    logger = getLogger(__name__)
    logger.debug(u'insecure_mode: %s, '
                 u'OCSP response cache file name: %s, '
                 u'PROXY_HOST: %s, PROXY_PORT: %s, PROXY_USER: %s '
                 u'PROXY_PASSWORD: %s',
                 FEATURE_INSECURE_MODE,
                 FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
                 PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASSWORD)
    if not FEATURE_INSECURE_MODE:
        v = SnowflakeOCSP(
            proxies=set_proxies(PROXY_HOST, PROXY_PORT, PROXY_USER,
                                PROXY_PASSWORD),
            ocsp_response_cache_url=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME
        ).validate(server_hostname, ret.connection)
        if not v:
            raise OperationalError(
                msg=(
                    u'The certificate is revoked or '
                    u'could not be validated: hostname={0}'.format(
                        server_hostname)),
                errno=ER_SERVER_CERTIFICATE_REVOKED)
    else:
        logger.info(u'THIS CONNECTION IS IN INSECURE '
                    u'MODE. IT MEANS THE CERTIFICATE WILL BE '
                    u'VALIDATED BUT THE CERTIFICATE REVOCATION '
                    u'STATUS WILL NOT BE CHECKED.')

    return ret


def inject_into_urllib3():
    """
    Monkey-patch urllib3 with PyOpenSSL-backed SSL-support and OCSP
    """
    logger = getLogger(__name__)
    logger.info(u'Injecting ssl_wrap_socket_with_ocsp')
    urllib3_connection.ssl_wrap_socket = ssl_wrap_socket_with_ocsp
