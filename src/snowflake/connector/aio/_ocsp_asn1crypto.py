from __future__ import annotations

import ssl
from collections import OrderedDict
from logging import getLogger

from aiohttp.client_proto import ResponseHandler
from asn1crypto.x509 import Certificate

from ..ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SnowflakeOCSPAsn1CryptoSync
from ._ocsp_snowflake import SnowflakeOCSP

logger = getLogger(__name__)


class SnowflakeOCSPAsn1Crypto(SnowflakeOCSP, SnowflakeOCSPAsn1CryptoSync):

    def extract_certificate_chain(self, connection: ResponseHandler):
        ssl_object = connection.transport.get_extra_info("ssl_object")
        if not ssl_object:
            raise RuntimeError(
                "Unable to get the SSL object from the asyncio transport to perform OCSP validation."
                "Please open an issue on the Snowflake Python Connector GitHub repository "
                "and provide your execution environment"
                " details: https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
                "As a workaround, you can create the connection with `disable_ocsp_checks=True` to skip OCSP Validation."
            )

        cert_map = OrderedDict()
        # in Python 3.10, get_unverified_chain was introduced as a
        # private method: https://github.com/python/cpython/pull/25467
        # which returns all the peer certs in the chain.
        # Python 3.13 will have the method get_unverified_chain publicly available on ssl.SSLSocket class
        # https://docs.python.org/pl/3.13/library/ssl.html#ssl.SSLSocket.get_unverified_chain
        unverified_chain = ssl_object._sslobj.get_unverified_chain()
        logger.debug("# of certificates: %s", len(unverified_chain))
        self._lazy_read_ca_bundle()
        for cert in unverified_chain:
            cert = Certificate.load(ssl.PEM_cert_to_DER_cert(cert.public_bytes()))
            logger.debug(
                "subject: %s, issuer: %s", cert.subject.native, cert.issuer.native
            )
            cert_map[cert.subject.sha256] = cert
            if cert.issuer.sha256 in SnowflakeOCSP.ROOT_CERTIFICATES_DICT:
                logger.debug(
                    "A trusted root certificate found: %s, stopping chain traversal here",
                    cert.subject.native,
                )
                break

        return self.create_pair_issuer_subject(cert_map)
