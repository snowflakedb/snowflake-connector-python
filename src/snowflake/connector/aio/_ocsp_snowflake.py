from __future__ import annotations

import asyncio
import json
import os
import time
from logging import getLogger
from typing import TYPE_CHECKING, Any

from aiohttp.client_proto import ResponseHandler
from asn1crypto.ocsp import CertId
from asn1crypto.x509 import Certificate

import snowflake.connector.ocsp_snowflake
from snowflake.connector.backoff_policies import exponential_backoff
from snowflake.connector.compat import OK
from snowflake.connector.constants import HTTP_HEADER_USER_AGENT
from snowflake.connector.errorcode import (
    ER_OCSP_FAILED_TO_CONNECT_CACHE_SERVER,
    ER_OCSP_RESPONSE_CACHE_DOWNLOAD_FAILED,
    ER_OCSP_RESPONSE_FETCH_EXCEPTION,
    ER_OCSP_RESPONSE_FETCH_FAILURE,
    ER_OCSP_RESPONSE_UNAVAILABLE,
    ER_OCSP_URL_INFO_MISSING,
)
from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.network import PYTHON_CONNECTOR_USER_AGENT
from snowflake.connector.ocsp_snowflake import (
    OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT,
    OCSPCache,
    OCSPResponseValidationResult,
)
from snowflake.connector.ocsp_snowflake import OCSPServer as OCSPServerSync
from snowflake.connector.ocsp_snowflake import OCSPTelemetryData
from snowflake.connector.ocsp_snowflake import SnowflakeOCSP as SnowflakeOCSPSync
from snowflake.connector.url_util import extract_top_level_domain_from_hostname

if TYPE_CHECKING:
    from snowflake.connector.aio._session_manager import SessionManager

logger = getLogger(__name__)


class OCSPServer(OCSPServerSync):
    async def download_cache_from_server(
        self, ocsp, *, session_manager: SessionManager
    ):
        if self.CACHE_SERVER_ENABLED:
            # if any of them is not cache, download the cache file from
            # OCSP response cache server.
            try:
                retval = await OCSPServer._download_ocsp_response_cache(
                    ocsp, self.CACHE_SERVER_URL, session_manager=session_manager
                )
                if not retval:
                    raise RevocationCheckError(
                        msg="OCSP Cache Server Unavailable.",
                        errno=ER_OCSP_RESPONSE_CACHE_DOWNLOAD_FAILED,
                    )
                logger.debug(
                    "downloaded OCSP response cache file from %s", self.CACHE_SERVER_URL
                )
                # len(OCSP_RESPONSE_VALIDATION_CACHE) is thread-safe, however, we do not want to
                # block for logging purpose, thus using len(OCSP_RESPONSE_VALIDATION_CACHE._cache) here.
                logger.debug(
                    "# of certificates: %u",
                    len(
                        snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE._cache
                    ),
                )
            except RevocationCheckError as rce:
                logger.debug(
                    "OCSP Response cache download failed. The client"
                    "will reach out to the OCSP Responder directly for"
                    "any missing OCSP responses %s\n" % rce.msg
                )
                raise

    @staticmethod
    async def _download_ocsp_response_cache(
        ocsp, url, *, session_manager: SessionManager, do_retry: bool = True
    ) -> bool:
        """Downloads OCSP response cache from the cache server."""
        headers = {HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT}
        sf_timeout = SnowflakeOCSP.OCSP_CACHE_SERVER_CONNECTION_TIMEOUT

        try:
            start_time = time.time()
            logger.debug("started downloading OCSP response cache file: %s", url)

            if ocsp.test_mode is not None:
                test_timeout = os.getenv(
                    "SF_TEST_OCSP_CACHE_SERVER_CONNECTION_TIMEOUT", None
                )
                sf_cache_server_url = os.getenv("SF_TEST_OCSP_CACHE_SERVER_URL", None)
                if test_timeout is not None:
                    sf_timeout = int(test_timeout)
                if sf_cache_server_url is not None:
                    url = sf_cache_server_url

            async with session_manager.use_session(url) as session:
                max_retry = SnowflakeOCSP.OCSP_CACHE_SERVER_MAX_RETRY if do_retry else 1
                sleep_time = 1
                backoff = exponential_backoff()()
                for _ in range(max_retry):
                    response = await session.get(
                        url,
                        timeout=sf_timeout,  # socket timeout
                        headers=headers,
                    )
                    if response.status == OK:
                        ocsp.decode_ocsp_response_cache(await response.json())
                        elapsed_time = time.time() - start_time
                        logger.debug(
                            "ended downloading OCSP response cache file. "
                            "elapsed time: %ss",
                            elapsed_time,
                        )
                        break
                    elif max_retry > 1:
                        sleep_time = next(backoff)
                        logger.debug(
                            "OCSP server returned %s. Retrying in %s(s)",
                            response.status,
                            sleep_time,
                        )
                    await asyncio.sleep(sleep_time)
                else:
                    logger.error(
                        "Failed to get OCSP response after %s attempt.", max_retry
                    )
                    return False
                return True
        except Exception as e:
            logger.debug("Failed to get OCSP response cache from %s: %s", url, e)
            raise RevocationCheckError(
                msg=f"Failed to get OCSP Response Cache from {url}: {e}",
                errno=ER_OCSP_FAILED_TO_CONNECT_CACHE_SERVER,
            )


class SnowflakeOCSP(SnowflakeOCSPSync):

    def __init__(
        self,
        ocsp_response_cache_uri=None,
        use_ocsp_cache_server=None,
        use_post_method: bool = True,
        use_fail_open: bool = True,
        root_certs_dict_lock_timeout: int = OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT,
        **kwargs,
    ) -> None:
        self.test_mode = os.getenv("SF_OCSP_TEST_MODE", None)

        if self.test_mode == "true":
            logger.debug("WARNING - DRIVER CONFIGURED IN TEST MODE")

        self._use_post_method = use_post_method
        self._root_certs_dict_lock_timeout = root_certs_dict_lock_timeout
        self.OCSP_CACHE_SERVER = OCSPServer(
            top_level_domain=extract_top_level_domain_from_hostname(
                kwargs.pop("hostname", None)
            )
        )

        self.debug_ocsp_failure_url = None

        if os.getenv("SF_OCSP_FAIL_OPEN") is not None:
            # failOpen Env Variable is for internal usage/ testing only.
            # Using it in production is not advised and not supported.
            self.FAIL_OPEN = os.getenv("SF_OCSP_FAIL_OPEN").lower() == "true"
        else:
            self.FAIL_OPEN = use_fail_open

        SnowflakeOCSP.OCSP_CACHE.reset_ocsp_response_cache_uri(ocsp_response_cache_uri)

        if not OCSPServer.is_enabled_new_ocsp_endpoint():
            self.OCSP_CACHE_SERVER.reset_ocsp_dynamic_cache_server_url(
                use_ocsp_cache_server
            )

        if not snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE:
            SnowflakeOCSP.OCSP_CACHE.read_file(self)

    async def validate(
        self,
        hostname: str | None,
        connection: ResponseHandler,
        *,
        session_manager: SessionManager,
        no_exception: bool = False,
    ) -> (
        list[
            tuple[
                Exception | None,
                Certificate,
                Certificate,
                CertId,
                str | bytes,
            ]
        ]
        | None
    ):
        """Validates the certificate is not revoked using OCSP."""
        logger.debug("validating certificate: %s", hostname)

        do_retry = SnowflakeOCSP.get_ocsp_retry_choice()

        m = not SnowflakeOCSP.OCSP_WHITELIST.match(hostname)
        if m or hostname.startswith("ocspssd"):
            logger.debug("skipping OCSP check: %s", hostname)
            return [None, None, None, None, None]

        if OCSPServer.is_enabled_new_ocsp_endpoint():
            self.OCSP_CACHE_SERVER.reset_ocsp_endpoint(hostname)

        telemetry_data = OCSPTelemetryData()
        telemetry_data.set_cache_enabled(self.OCSP_CACHE_SERVER.CACHE_SERVER_ENABLED)
        telemetry_data.set_disable_ocsp_checks(False)
        telemetry_data.set_sfc_peer_host(hostname)
        telemetry_data.set_fail_open(self.is_enabled_fail_open())

        try:
            cert_data = self.extract_certificate_chain(connection)
        except RevocationCheckError:
            telemetry_data.set_event_sub_type(
                OCSPTelemetryData.CERTIFICATE_EXTRACTION_FAILED
            )
            logger.debug(
                telemetry_data.generate_telemetry_data("RevocationCheckFailure")
            )
            return None

        return await self._validate(
            hostname,
            cert_data,
            telemetry_data,
            session_manager=session_manager,
            do_retry=do_retry,
            no_exception=no_exception,
        )

    async def _validate(
        self,
        hostname: str | None,
        cert_data: list[tuple[Certificate, Certificate]],
        telemetry_data: OCSPTelemetryData,
        *,
        session_manager: SessionManager,
        do_retry: bool = True,
        no_exception: bool = False,
    ) -> list[tuple[Exception | None, Certificate, Certificate, CertId, bytes]]:
        """Validate certs sequentially if OCSP response cache server is used."""
        results = await self._validate_certificates_sequential(
            cert_data,
            telemetry_data,
            hostname=hostname,
            do_retry=do_retry,
            session_manager=session_manager,
        )

        SnowflakeOCSP.OCSP_CACHE.update_file(self)

        any_err = False
        for err, _, _, _, _ in results:
            if isinstance(err, RevocationCheckError):
                err.msg += f" for {hostname}"
            if not no_exception and err is not None:
                raise err
            elif err is not None:
                any_err = True

        logger.debug("ok" if not any_err else "failed")
        return results

    async def _validate_issue_subject(
        self,
        issuer: Certificate,
        subject: Certificate,
        telemetry_data: OCSPTelemetryData,
        *,
        session_manager: SessionManager,
        hostname: str | None = None,
        do_retry: bool = True,
    ) -> tuple[
        tuple[bytes, bytes, bytes],
        [Exception | None, Certificate, Certificate, CertId, bytes],
    ]:
        cert_id, req = self.create_ocsp_request(issuer, subject)
        cache_key = self.decode_cert_id_key(cert_id)
        ocsp_response_validation_result = (
            snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE.get(
                cache_key
            )
        )

        if (
            ocsp_response_validation_result is None
            or not ocsp_response_validation_result.validated
        ):
            r = await self.validate_by_direct_connection(
                issuer,
                subject,
                telemetry_data,
                hostname=hostname,
                session_manager=session_manager,
                do_retry=do_retry,
                cache_key=cache_key,
            )
            return cache_key, r
        else:
            return cache_key, (
                ocsp_response_validation_result.exception,
                ocsp_response_validation_result.issuer,
                ocsp_response_validation_result.subject,
                ocsp_response_validation_result.cert_id,
                ocsp_response_validation_result.ocsp_response,
            )

    async def _check_ocsp_response_cache_server(
        self,
        cert_data: list[tuple[Certificate, Certificate]],
        *,
        session_manager: SessionManager,
    ) -> None:
        """Checks if OCSP response is in cache, and if not it downloads the OCSP response cache from the server.

        Args:
          cert_data: Tuple of issuer and subject certificates.
        """
        in_cache = False
        for issuer, subject in cert_data:
            # check if any OCSP response is NOT in cache
            cert_id, _ = self.create_ocsp_request(issuer, subject)
            in_cache, _ = SnowflakeOCSP.OCSP_CACHE.find_cache(self, cert_id, subject)
            if not in_cache:
                # not found any
                break

        if not in_cache:
            await self.OCSP_CACHE_SERVER.download_cache_from_server(
                self, session_manager=session_manager
            )

    async def _validate_certificates_sequential(
        self,
        cert_data: list[tuple[Certificate, Certificate]],
        telemetry_data: OCSPTelemetryData,
        *,
        session_manager: SessionManager,
        hostname: str | None = None,
        do_retry: bool = True,
    ) -> list[tuple[Exception | None, Certificate, Certificate, CertId, bytes]]:
        try:
            await self._check_ocsp_response_cache_server(
                cert_data, session_manager=session_manager
            )
        except RevocationCheckError as rce:
            telemetry_data.set_event_sub_type(
                OCSPTelemetryData.ERROR_CODE_MAP[rce.errno]
            )
        except Exception as ex:
            logger.debug(
                "Caught unknown exception - %s. Continue to validate by direct connection",
                str(ex),
            )

        to_update_cache_dict = {}

        task_results = await asyncio.gather(
            *[
                self._validate_issue_subject(
                    issuer,
                    subject,
                    hostname=hostname,
                    telemetry_data=telemetry_data,
                    do_retry=do_retry,
                    session_manager=session_manager,
                )
                for issuer, subject in cert_data
            ]
        )
        results = [validate_result for _, validate_result in task_results]
        for cache_key, validate_result in task_results:
            if validate_result[0] is not None or validate_result[4] is not None:
                to_update_cache_dict[cache_key] = OCSPResponseValidationResult(
                    *validate_result,
                    ts=int(time.time()),
                    validated=True,
                )
                OCSPCache.CACHE_UPDATED = True

        snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE.update(
            to_update_cache_dict
        )
        return results

    async def validate_by_direct_connection(
        self,
        issuer: Certificate,
        subject: Certificate,
        telemetry_data: OCSPTelemetryData,
        *,
        session_manager: SessionManager,
        hostname: str = None,
        do_retry: bool = True,
        **kwargs: Any,
    ) -> tuple[Exception | None, Certificate, Certificate, CertId, bytes]:
        cert_id, req = self.create_ocsp_request(issuer, subject)
        cache_status, ocsp_response = self.is_cert_id_in_cache(
            cert_id, subject, **kwargs
        )

        try:
            if not cache_status:
                telemetry_data.set_cache_hit(False)
                logger.debug("getting OCSP response from CA's OCSP server")
                ocsp_response = await self._fetch_ocsp_response(
                    req,
                    subject,
                    cert_id,
                    telemetry_data,
                    session_manager=session_manager,
                    hostname=hostname,
                    do_retry=do_retry,
                )
            else:
                ocsp_url = self.extract_ocsp_url(subject)
                cert_id_enc = self.encode_cert_id_base64(
                    self.decode_cert_id_key(cert_id)
                )
                telemetry_data.set_cache_hit(True)
                self.debug_ocsp_failure_url = SnowflakeOCSP.create_ocsp_debug_info(
                    self, req, ocsp_url
                )
                telemetry_data.set_ocsp_url(ocsp_url)
                telemetry_data.set_ocsp_req(req)
                telemetry_data.set_cert_id(cert_id_enc)
                logger.debug("using OCSP response cache")

            if not ocsp_response:
                telemetry_data.set_event_sub_type(
                    OCSPTelemetryData.OCSP_RESPONSE_UNAVAILABLE
                )
                raise RevocationCheckError(
                    msg="Could not retrieve OCSP Response. Cannot perform Revocation Check",
                    errno=ER_OCSP_RESPONSE_UNAVAILABLE,
                )
            try:
                self.process_ocsp_response(issuer, cert_id, ocsp_response)
                err = None
            except RevocationCheckError as op_er:
                telemetry_data.set_event_sub_type(
                    OCSPTelemetryData.ERROR_CODE_MAP[op_er.errno]
                )
                raise op_er

        except RevocationCheckError as rce:
            telemetry_data.set_error_msg(rce.msg)
            err = self.verify_fail_open(rce, telemetry_data)

        except Exception as ex:
            logger.debug("OCSP Validation failed %s", str(ex))
            telemetry_data.set_error_msg(str(ex))
            err = self.verify_fail_open(ex, telemetry_data)
            SnowflakeOCSP.OCSP_CACHE.delete_cache(self, cert_id)

        return err, issuer, subject, cert_id, ocsp_response

    async def _fetch_ocsp_response(
        self,
        ocsp_request,
        subject,
        cert_id,
        telemetry_data,
        *,
        session_manager: SessionManager,
        hostname=None,
        do_retry: bool = True,
    ):
        """Fetches OCSP response using OCSPRequest."""
        sf_timeout = SnowflakeOCSP.CA_OCSP_RESPONDER_CONNECTION_TIMEOUT
        ocsp_url = self.extract_ocsp_url(subject)
        cert_id_enc = self.encode_cert_id_base64(self.decode_cert_id_key(cert_id))
        if not ocsp_url:
            telemetry_data.set_event_sub_type(OCSPTelemetryData.OCSP_URL_MISSING)
            raise RevocationCheckError(
                msg="No OCSP URL found in cert. Cannot perform Certificate Revocation check",
                errno=ER_OCSP_URL_INFO_MISSING,
            )
        headers = {HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT}

        if not OCSPServer.is_enabled_new_ocsp_endpoint():
            actual_method = "post" if self._use_post_method else "get"
            if self.OCSP_CACHE_SERVER.OCSP_RETRY_URL:
                # no POST is supported for Retry URL at the moment.
                actual_method = "get"

            if actual_method == "get":
                b64data = self.decode_ocsp_request_b64(ocsp_request)
                target_url = self.OCSP_CACHE_SERVER.generate_get_url(ocsp_url, b64data)
                payload = None
            else:
                target_url = ocsp_url
                payload = self.decode_ocsp_request(ocsp_request)
                headers["Content-Type"] = "application/ocsp-request"
        else:
            actual_method = "post"
            target_url = self.OCSP_CACHE_SERVER.OCSP_RETRY_URL
            ocsp_req_enc = self.decode_ocsp_request_b64(ocsp_request)

            payload = json.dumps(
                {
                    "hostname": hostname,
                    "ocsp_request": ocsp_req_enc,
                    "cert_id": cert_id_enc,
                    "ocsp_responder_url": ocsp_url,
                }
            )
            headers["Content-Type"] = "application/json"

        telemetry_data.set_ocsp_connection_method(actual_method)
        if self.test_mode is not None:
            logger.debug("WARNING - DRIVER IS CONFIGURED IN TESTMODE.")
            test_ocsp_url = os.getenv("SF_TEST_OCSP_URL", None)
            test_timeout = os.getenv(
                "SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT", None
            )
            if test_timeout is not None:
                sf_timeout = int(test_timeout)
            if test_ocsp_url is not None:
                target_url = test_ocsp_url

        self.debug_ocsp_failure_url = SnowflakeOCSP.create_ocsp_debug_info(
            self, ocsp_request, ocsp_url
        )
        telemetry_data.set_ocsp_req(self.decode_ocsp_request_b64(ocsp_request))
        telemetry_data.set_ocsp_url(ocsp_url)
        telemetry_data.set_cert_id(cert_id_enc)

        ret = None
        logger.debug("url: %s", target_url)
        sf_max_retry = SnowflakeOCSP.CA_OCSP_RESPONDER_MAX_RETRY_FO
        if not self.is_enabled_fail_open():
            sf_max_retry = SnowflakeOCSP.CA_OCSP_RESPONDER_MAX_RETRY_FC

        async with session_manager.use_session(target_url) as session:
            max_retry = sf_max_retry if do_retry else 1
            sleep_time = 1
            backoff = exponential_backoff()()
            for _ in range(max_retry):
                try:
                    response = await session.request(
                        headers=headers,
                        method=actual_method,
                        url=target_url,
                        timeout=sf_timeout,
                        data=payload,
                    )
                    if response.status == OK:
                        logger.debug(
                            "OCSP response was successfully returned from OCSP "
                            "server."
                        )
                        ret = await response.content.read()
                        break
                    elif max_retry > 1:
                        sleep_time = next(backoff)
                        logger.debug(
                            "OCSP server returned %s. Retrying in %s(s)",
                            response.status,
                            sleep_time,
                        )
                    await asyncio.sleep(sleep_time)
                except Exception as ex:
                    if max_retry > 1:
                        sleep_time = next(backoff)
                        logger.debug(
                            "Could not fetch OCSP Response from server"
                            "Retrying in %s(s)",
                            sleep_time,
                        )
                        await asyncio.sleep(sleep_time)
                    else:
                        telemetry_data.set_event_sub_type(
                            OCSPTelemetryData.OCSP_RESPONSE_FETCH_EXCEPTION
                        )
                        raise RevocationCheckError(
                            msg="Could not fetch OCSP Response from server. Consider"
                            "checking your whitelists : Exception - {}".format(str(ex)),
                            errno=ER_OCSP_RESPONSE_FETCH_EXCEPTION,
                        )
            else:
                logger.error(
                    "Failed to get OCSP response after {} attempt. Consider checking "
                    "for OCSP URLs being blocked".format(max_retry)
                )
                telemetry_data.set_event_sub_type(
                    OCSPTelemetryData.OCSP_RESPONSE_FETCH_FAILURE
                )
                raise RevocationCheckError(
                    msg="Failed to get OCSP response after {} attempt.".format(
                        max_retry
                    ),
                    errno=ER_OCSP_RESPONSE_FETCH_FAILURE,
                )

        return ret
