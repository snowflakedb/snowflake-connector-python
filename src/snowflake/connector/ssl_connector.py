#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import ssl
from typing import List

import aiohttp
import certifi
from aiohttp.client_proto import ResponseHandler
from cryptography import x509
from OpenSSL.SSL import X509

from .constants import OCSPMode
from .errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from .errors import OperationalError

DEFAULT_OCSP_MODE: OCSPMode = OCSPMode.FAIL_OPEN
FEATURE_OCSP_MODE: OCSPMode = DEFAULT_OCSP_MODE

"""
OCSP Response cache file name
"""
FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME: str | None = None

log = logging.getLogger(__name__)

# YICHUAN: This class simply overrides aiohttp.TCPConnector to perform certificate revocation checks via OCSP after the
# TLS handshake is completed with the server, and before any data is exchanged
# Note that normally, OCSP checks are done DURING the TLS handshake, before the client exchanges its key; there are a
# few concerns this may raise, but currently the Python Connector does OCSP checks after the TLS handshake already

# In ssl_wrap_socket.ssl_wrap_socket_with_ocsp, we invoke SFOCSP using "ret = ssl_.ssl_wrap_socket(*args, **kwargs)",
# at which point ssl_.ssl_wrap_socket has already completed the TLS handshake, so really we're doing the same thing


# YICHUAN: ssl.create_default_context already uses (usually) the strictest security settings as per the link below
# https://docs.python.org/3/library/ssl.html#ssl.create_default_context
# I've traced through the code in urllib3.create_urllib3_context and tried to make sure that we're creating SSLContext
# with the same settings as before, but I can't guarantee it because the code paths are complex
def create_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # YICHUAN: In requests.HTTPAdapter.cert_verify urllib3 ends up using requests.utils.DEFAULT_CA_BUNDLE_PATH to pass
    # as the cafile location, which calls certifi.where in the back
    context.load_verify_locations(cafile=certifi.where())
    return context


class SnowflakeSSLConnector(aiohttp.TCPConnector):
    async def _create_connection(
        self, req: aiohttp.ClientResponse, traces: list[Trace], timeout: ClientTimeout
    ) -> ResponseHandler:
        """Create connection.

        Has same keyword arguments as BaseEventLoop.create_connection.
        """
        proto = await super()._create_connection(req, traces, timeout)

        # YICHUAN: Same as get_peer_cert_chain in PyOpenSSL, but we should consider using get_verified_chain instead
        # https://github.com/python/cpython/issues/62433#issuecomment-1093619239
        unverified_chain = (
            proto.transport._ssl_protocol._sslobj._sslobj.get_unverified_chain()
        )
        peer_cert_chain_pyopenssl = [
            X509.from_cryptography(
                x509.load_der_x509_certificate(cert.public_bytes(ssl._ssl.ENCODING_DER))
            )
            for cert in unverified_chain
        ]

        log.debug(
            "OCSP Mode: %s, " "OCSP response cache file name: %s",
            FEATURE_OCSP_MODE.name,
            FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
        )
        if FEATURE_OCSP_MODE != OCSPMode.INSECURE:
            from .ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP

            v = SFOCSP(
                ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
                use_fail_open=FEATURE_OCSP_MODE == OCSPMode.FAIL_OPEN,
            ).validate(req.host, peer_cert_chain_pyopenssl)
            if not v:
                raise OperationalError(
                    msg=(
                        "The certificate is revoked or "
                        "could not be validated: hostname={}".format(req.host)
                    ),
                    errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
                )
        else:
            log.info(
                "THIS CONNECTION IS IN INSECURE "
                "MODE. IT MEANS THE CERTIFICATE WILL BE "
                "VALIDATED BUT THE CERTIFICATE REVOCATION "
                "STATUS WILL NOT BE CHECKED."
            )

        return proto
