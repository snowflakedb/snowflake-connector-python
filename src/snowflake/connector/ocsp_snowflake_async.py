#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict

import aiohttp
from asn1crypto.ocsp import CertId
from asn1crypto.x509 import Certificate
from OpenSSL.crypto import X509

from .backoff_policies import DEFAULT_TIMEOUT_GENERATOR_FUNCTION
from .compat import OK
from .constants import HTTP_HEADER_USER_AGENT
from .errorcode import (
    ER_OCSP_RESPONSE_FETCH_EXCEPTION,
    ER_OCSP_RESPONSE_FETCH_FAILURE,
    ER_OCSP_RESPONSE_UNAVAILABLE,
    ER_OCSP_URL_INFO_MISSING,
)
from .errors import RevocationCheckError
from .network import PYTHON_CONNECTOR_USER_AGENT
from .network_async import (
    get_default_aiohttp_session_request_kwargs,
    make_client_session,
)
from .ocsp_snowflake import (
    OCSP_RESPONSE_VALIDATION_CACHE,
    OCSPCache,
    OCSPResponseValidationResult,
    OCSPServer,
    OCSPTelemetryData,
    SnowflakeOCSP,
    logger,
)

# YICHUAN: Since some OCSP related modules have module-level state, NO STAR IMPORTS!


# YICHUAN: This class's purpose is to override SnowflakeOCSP._validate_certificates_sequential and make its execution
# concurrent via SnowflakeOCSPAsync._validate_certificates_concurrent_async
# Most of the code is duplicated from SnowflakeOCSP, which is unfortunate but necessary without some fancy and probably
# excessively complicated wrapper solutions


class SnowflakeOCSPAsync(SnowflakeOCSP):
    async def validate_async(
        self,
        hostname: str | None,
        peer_cert_chain: list[X509],
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
        telemetry_data.set_insecure_mode(False)
        telemetry_data.set_sfc_peer_host(hostname)
        telemetry_data.set_fail_open(self.is_enabled_fail_open())

        try:
            cert_data = self.extract_certificate_chain(peer_cert_chain)
        except RevocationCheckError:
            telemetry_data.set_event_sub_type(
                OCSPTelemetryData.CERTIFICATE_EXTRACTION_FAILED
            )
            logger.debug(
                telemetry_data.generate_telemetry_data("RevocationCheckFailure")
            )
            return None

        return await self._validate_async(
            hostname, cert_data, telemetry_data, do_retry, no_exception
        )

    async def _validate_async(
        self,
        hostname: str | None,
        cert_data: list[tuple[Certificate, Certificate]],
        telemetry_data: OCSPTelemetryData,
        do_retry: bool = True,
        no_exception: bool = False,
    ) -> list[tuple[Exception | None, Certificate, Certificate, CertId, bytes]]:
        """Validate certs CONCURRENTLY if OCSP response cache server is used."""
        results = await self._validate_certificates_concurrent_async(
            cert_data, telemetry_data, hostname, do_retry=do_retry
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

    async def _validate_certificates_concurrent_async(
        self,
        cert_data: list[tuple[Certificate, Certificate]],
        telemetry_data: OCSPTelemetryData,
        hostname: str | None = None,
        do_retry: bool = True,
    ) -> list[tuple[Exception | None, Certificate, Certificate, CertId, bytes]]:
        try:
            self._check_ocsp_response_cache_server(cert_data)
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
        results = await asyncio.gather(
            *[
                self._validate_issuer_subject_async(
                    issuer,
                    subject,
                    to_update_cache_dict=to_update_cache_dict,
                    hostname=hostname,
                    telemetry_data=telemetry_data,
                    do_retry=do_retry,
                )
                for issuer, subject in cert_data
            ]
        )
        OCSP_RESPONSE_VALIDATION_CACHE.update(to_update_cache_dict)
        return results

    async def _validate_issuer_subject_async(
        self,
        issuer: Certificate,
        subject: Certificate,
        to_update_cache_dict: dict,
        hostname: str | None,
        telemetry_data: OCSPTelemetryData,
        do_retry: bool,
    ) -> tuple[Exception | None, Certificate, Certificate, CertId, bytes]:
        cert_id, _ = self.create_ocsp_request(issuer=issuer, subject=subject)
        cache_key = self.decode_cert_id_key(cert_id)
        ocsp_response_validation_result = OCSP_RESPONSE_VALIDATION_CACHE.get(cache_key)

        if (
            ocsp_response_validation_result is None
            or not ocsp_response_validation_result.validated
        ):
            # r is a tuple of (err, issuer, subject, cert_id, ocsp_response)
            r = await self._validate_by_direct_connection_async(
                issuer,
                subject,
                telemetry_data,
                hostname,
                do_retry=do_retry,
                cache_key=cache_key,
            )

            # When OCSP server is down, the validation fails and the oscp_response will be None, and in fail open
            # case, we will also reset err to None.
            # In this case we don't need to write the response to cache because there is no information from a
            # connection error.
            if r[0] is not None or r[4] is not None:
                to_update_cache_dict[cache_key] = OCSPResponseValidationResult(
                    *r,
                    ts=int(time.time()),
                    validated=True,
                )
                OCSPCache.CACHE_UPDATED = True
            return r
        else:
            return (
                ocsp_response_validation_result.exception,
                ocsp_response_validation_result.issuer,
                ocsp_response_validation_result.subject,
                ocsp_response_validation_result.cert_id,
                ocsp_response_validation_result.ocsp_response,
            )

    async def _validate_by_direct_connection_async(
        self,
        issuer: Certificate,
        subject: Certificate,
        telemetry_data: OCSPTelemetryData,
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
                ocsp_response = await self._fetch_ocsp_response_async(
                    req, subject, cert_id, telemetry_data, hostname, do_retry
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

    async def _fetch_ocsp_response_async(
        self,
        ocsp_request,
        subject,
        cert_id,
        telemetry_data,
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

        async with make_client_session(asyncio.get_running_loop()) as session:
            max_retry = sf_max_retry if do_retry else 1
            sleep_time = 1
            backoff = DEFAULT_TIMEOUT_GENERATOR_FUNCTION()
            for _ in range(max_retry):
                try:
                    response = await session.request(
                        actual_method,
                        target_url,
                        headers=headers,
                        data=payload,
                        timeout=aiohttp.ClientTimeout(sf_timeout),
                        **get_default_aiohttp_session_request_kwargs(target_url),
                    )
                    if response.status == OK:
                        logger.debug(
                            "OCSP response was successfully returned from OCSP "
                            "server."
                        )
                        ret = await response.read()
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
