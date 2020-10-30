# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

#
# SSL wrap socket for PyOpenSSL.
# Mostly copied from
#
# https://github.com/shazow/urllib3/blob/master/urllib3/contrib/pyopenssl.py
#
# and added OCSP validator on the top.

import logging
import time
from functools import wraps
from inspect import getfullargspec as get_args
from socket import socket

import certifi
import OpenSSL.SSL
import requests.packages.urllib3.connection as connection_
import requests.packages.urllib3.util.ssl_ as ssl_
from urllib3.contrib.pyopenssl import PyOpenSSLContext

from .constants import OCSPMode
from .errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from .errors import OperationalError

FEATURE_OCSP_MODE = OCSPMode.FAIL_OPEN

"""
OCSP Response cache file name
"""
FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = None

log = logging.getLogger(__name__)


def inject_into_urllib3():
    """Monkey-patch urllib3 with PyOpenSSL-backed SSL-support and OCSP."""
    log.debug('Injecting ssl_wrap_socket_with_ocsp')
    connection_.ssl_wrap_socket = ssl_wrap_socket_with_ocsp


@wraps(ssl_.ssl_wrap_socket)
def ssl_wrap_socket_with_ocsp(*args, **kwargs):
    # Extract host_name
    hostname_index = get_args(ssl_.ssl_wrap_socket).args.index('server_hostname')
    server_hostname = args[hostname_index] if len(args) > hostname_index else kwargs.get('server_hostname', None)
    # Remove context if present
    ssl_context_index = get_args(ssl_.ssl_wrap_socket).args.index('ssl_context')
    context_in_args = len(args) > ssl_context_index
    ssl_context = args[hostname_index] if context_in_args else kwargs.get('ssl_context', None)
    if not isinstance(ssl_context, PyOpenSSLContext):
        # Create new default context
        if context_in_args:
            new_args = list(args)
            new_args[ssl_context_index] = None
            args = tuple(new_args)
        else:
            del kwargs['ssl_context']
    # Fix ca certs location
    ca_certs_index = get_args(ssl_.ssl_wrap_socket).args.index('ca_certs')
    ca_certs_in_args = len(args) > ca_certs_index
    if not ca_certs_in_args and not kwargs.get('ca_certs'):
        kwargs['ca_certs'] = certifi.where()

    ret = ssl_.ssl_wrap_socket(*args, **kwargs)

    global FEATURE_OCSP_MODE
    global FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME

    from .ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP

    log.debug('OCSP Mode: %s, '
              'OCSP response cache file name: %s',
              FEATURE_OCSP_MODE.name,
              FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME)
    if FEATURE_OCSP_MODE != OCSPMode.INSECURE:
        v = SFOCSP(
            ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
            use_fail_open=FEATURE_OCSP_MODE == OCSPMode.FAIL_OPEN
        ).validate(server_hostname, ret.connection)
        if not v:
            raise OperationalError(
                msg=(
                    'The certificate is revoked or '
                    'could not be validated: hostname={}'.format(
                        server_hostname)),
                errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED)
    else:
        log.info('THIS CONNECTION IS IN INSECURE '
                 'MODE. IT MEANS THE CERTIFICATE WILL BE '
                 'VALIDATED BUT THE CERTIFICATE REVOCATION '
                 'STATUS WILL NOT BE CHECKED.')

    return ret


def _openssl_connect(hostname, port=443, max_retry=20):
    """The OpenSSL connection without validating certificates.

    This is used to diagnose SSL issues.
    """
    err = None
    sleeping_time = 1
    for _ in range(max_retry):
        try:
            client = socket()
            # client.settimeout(5)
            client.connect((hostname, port))
            client_ssl = OpenSSL.SSL.Connection(
                OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD), client)
            client_ssl.set_connect_state()
            client_ssl.set_tlsext_host_name(hostname.encode('utf-8'))
            client_ssl.do_handshake()
            return client_ssl
        except (OpenSSL.SSL.SysCallError, ConnectionRefusedError, TimeoutError, OSError) as ex:
            err = ex
            sleeping_time = min(sleeping_time * 2, 16)
            time.sleep(sleeping_time)
    if err:
        raise err
