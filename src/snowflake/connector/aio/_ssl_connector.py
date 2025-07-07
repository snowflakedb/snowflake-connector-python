#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import aiohttp
from aiohttp import ClientRequest, ClientTimeout
from aiohttp.client_proto import ResponseHandler
from aiohttp.connector import Connection

from snowflake.connector.constants import OCSPMode

from .. import OperationalError
from ..errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from ..ssl_wrap_socket import FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME
from ._ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto

if TYPE_CHECKING:
    from aiohttp.tracing import Trace

log = logging.getLogger(__name__)


class SnowflakeSSLConnector(aiohttp.TCPConnector):
    def __init__(self, *args, **kwargs):
        self._snowflake_ocsp_mode = kwargs.pop(
            "snowflake_ocsp_mode", OCSPMode.FAIL_OPEN
        )
        if self._snowflake_ocsp_mode == OCSPMode.FAIL_OPEN and sys.version_info < (
            3,
            10,
        ):
            raise RuntimeError(
                "Async Snowflake Python Connector requires Python 3.10+ for OCSP validation related features. "
                "Please open a feature request issue in github if your want to use Python 3.9 or lower: "
                "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
            )

        super().__init__(*args, **kwargs)

    async def connect(
        self, req: ClientRequest, traces: list[Trace], timeout: ClientTimeout
    ) -> Connection:
        connection = await super().connect(req, traces, timeout)
        protocol = connection.protocol
        if (
            req.is_ssl()
            and protocol is not None
            and not getattr(protocol, "_snowflake_ocsp_validated", False)
        ):
            if self._snowflake_ocsp_mode == OCSPMode.DISABLE_OCSP_CHECKS:
                log.debug(
                    "This connection does not perform OCSP checks. "
                    "Revocation status of the certificate will not be checked against OCSP Responder."
                )
            else:
                await self.validate_ocsp(req.url.host, protocol)
                protocol._snowflake_ocsp_validated = True
        return connection

    async def validate_ocsp(self, hostname: str, protocol: ResponseHandler):

        v = await SnowflakeOCSPAsn1Crypto(
            ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
            use_fail_open=self._snowflake_ocsp_mode == OCSPMode.FAIL_OPEN,
            hostname=hostname,
        ).validate(hostname, protocol)
        if not v:
            raise OperationalError(
                msg=(
                    "The certificate is revoked or "
                    "could not be validated: hostname={}".format(hostname)
                ),
                errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
            )
