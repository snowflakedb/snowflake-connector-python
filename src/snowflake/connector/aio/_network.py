from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import logging
import re
import uuid
from typing import TYPE_CHECKING, Any, AsyncGenerator

import OpenSSL.SSL

from ..compat import FORBIDDEN, OK, UNAUTHORIZED, urlencode, urlparse, urlsplit
from ..constants import (
    _CONNECTIVITY_ERR_MSG,
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from ..errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_CONNECTION_TIMEOUT,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_FAILED_TO_RENEW_SESSION,
    ER_FAILED_TO_REQUEST,
    ER_HTTP_GENERAL_ERROR,
    ER_RETRYABLE_CODE,
)
from ..errors import (
    DatabaseError,
    Error,
    ForbiddenError,
    HttpError,
    OperationalError,
    ProgrammingError,
    RefreshTokenError,
    RevocationCheckError,
)
from ..network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    BAD_REQUEST_GS_CODE,
    CONTENT_TYPE_APPLICATION_JSON,
    DEFAULT_SOCKET_CONNECT_TIMEOUT,
    EXTERNAL_BROWSER_AUTHENTICATOR,
    HEADER_AUTHORIZATION_KEY,
    HEADER_SNOWFLAKE_TOKEN,
    ID_TOKEN_EXPIRED_GS_CODE,
    IMPLEMENTATION,
    MASTER_TOKEN_EXPIRED_GS_CODE,
    MASTER_TOKEN_INVALD_GS_CODE,
    MASTER_TOKEN_NOTFOUND_GS_CODE,
    NO_TOKEN,
    PLATFORM,
    PYTHON_VERSION,
    QUERY_IN_PROGRESS_ASYNC_CODE,
    QUERY_IN_PROGRESS_CODE,
    REQUEST_ID,
    REQUEST_TYPE_RENEW,
    SESSION_EXPIRED_GS_CODE,
    SNOWFLAKE_CONNECTOR_VERSION,
    ReauthenticationRequest,
    RetryRequest,
)
from ..network import SnowflakeRestful as SnowflakeRestfulSync
from ..network import (
    SnowflakeRestfulJsonEncoder,
    get_http_retryable_error,
    is_econnreset_exception,
    is_login_request,
    is_retryable_http_code,
)
from ..secret_detector import SecretDetector
from ..sqlstate import (
    SQLSTATE_CONNECTION_NOT_EXISTS,
    SQLSTATE_CONNECTION_REJECTED,
    SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
)
from ..time_util import TimeoutBackoffCtx
from ._description import CLIENT_NAME
from ._session_manager import (
    SessionManager,
    SessionManagerFactory,
    SnowflakeSSLConnectorFactory,
)

if TYPE_CHECKING:
    from snowflake.connector.aio import SnowflakeConnection

logger = logging.getLogger(__name__)

PYTHON_CONNECTOR_USER_AGENT = f"{CLIENT_NAME}/{SNOWFLAKE_CONNECTOR_VERSION} ({PLATFORM}) {IMPLEMENTATION}/{PYTHON_VERSION}"

try:
    import aiohttp
except ImportError:
    logger.warning("Please install aiohttp to use asyncio features.")
    raise


def raise_okta_unauthorized_error(
    connection: SnowflakeConnection | None, response: aiohttp.ClientResponse
) -> None:
    Error.errorhandler_wrapper(
        connection,
        None,
        DatabaseError,
        {
            "msg": f"Failed to get authentication by OKTA: {response.status}: {response.reason}",
            "errno": ER_FAILED_TO_CONNECT_TO_DB,
            "sqlstate": SQLSTATE_CONNECTION_REJECTED,
        },
    )


def raise_failed_request_error(
    connection: SnowflakeConnection | None,
    url: str,
    method: str,
    response: aiohttp.ClientResponse,
) -> None:
    Error.errorhandler_wrapper(
        connection,
        None,
        HttpError,
        {
            "msg": f"{response.status} {response.reason}: {method} {urlsplit(url).netloc}{urlsplit(url).path}",
            "errno": ER_HTTP_GENERAL_ERROR + response.status,
            "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
        },
    )


class SnowflakeRestful(SnowflakeRestfulSync):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        protocol: str = "http",
        inject_client_pause: int = 0,
        connection: SnowflakeConnection | None = None,
        session_manager: SessionManager | None = None,
    ):
        super().__init__(host, port, protocol, inject_client_pause, connection)
        self._lock_token = asyncio.Lock()

        if session_manager is None:
            session_manager = (
                connection._session_manager
                if (connection and connection._session_manager)
                else SessionManagerFactory.get_manager(
                    connector_factory=SnowflakeSSLConnectorFactory()
                )
            )
        self._session_manager = session_manager

    async def close(self) -> None:
        if hasattr(self, "_token"):
            del self._token
        if hasattr(self, "_master_token"):
            del self._master_token
        if hasattr(self, "_id_token"):
            del self._id_token
        if hasattr(self, "_mfa_token"):
            del self._mfa_token

        await self._session_manager.close()

    async def request(
        self,
        url,
        body=None,
        method: str = "post",
        client: str = "sfsql",
        timeout: int | None = None,
        _no_results: bool = False,
        _include_retry_params: bool = False,
        _no_retry: bool = False,
    ):
        # log to reflect vendored.urllib3.connectionpool:connectionpool.py:474
        logger.debug("%s %s", method.upper(), url)
        if body is None:
            body = {}
        if self.master_token is None and self.token is None:
            Error.errorhandler_wrapper(
                self._connection,
                None,
                DatabaseError,
                {
                    "msg": "Connection is closed",
                    "errno": ER_CONNECTION_IS_CLOSED,
                    "sqlstate": SQLSTATE_CONNECTION_NOT_EXISTS,
                },
            )

        if client == "sfsql":
            accept_type = ACCEPT_TYPE_APPLICATION_SNOWFLAKE
        else:
            accept_type = CONTENT_TYPE_APPLICATION_JSON

        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: accept_type,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        try:
            # SNOW-1763555: inject OpenTelemetry headers if available specifically in WC3 format
            #  into our request headers in case tracing is enabled. This should make sure that
            #  our requests are accounted for properly if OpenTelemetry is used by users.
            from opentelemetry.trace.propagation.tracecontext import (
                TraceContextTextMapPropagator,
            )

            TraceContextTextMapPropagator().inject(headers)
        except Exception:
            logger.debug(
                "Opentelemtry otel injection failed",
                exc_info=True,
            )
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        if method == "post":
            return await self._post_request(
                url,
                headers,
                json.dumps(body, cls=SnowflakeRestfulJsonEncoder),
                token=self.token,
                _no_results=_no_results,
                timeout=timeout,
                _include_retry_params=_include_retry_params,
                no_retry=_no_retry,
            )
        else:
            return await self._get_request(
                url,
                headers,
                token=self.token,
                timeout=timeout,
            )

    async def update_tokens(
        self,
        session_token,
        master_token,
        master_validity_in_seconds=None,
        id_token=None,
        mfa_token=None,
    ) -> None:
        """Updates session and master tokens and optionally temporary credential."""
        async with self._lock_token:
            self._token = session_token
            self._master_token = master_token
            self._id_token = id_token
            self._mfa_token = mfa_token
            self._master_validity_in_seconds = master_validity_in_seconds

    async def _renew_session(self):
        """Renew a session and master token."""
        return await self._token_request(REQUEST_TYPE_RENEW)

    async def _token_request(self, request_type):
        logger.debug(
            "updating session. master_token: {}".format(
                "****" if self.master_token else None
            )
        )
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        request_id = str(uuid.uuid4())
        logger.debug("request_id: %s", request_id)
        url = "/session/token-request?" + urlencode({REQUEST_ID: request_id})

        # NOTE: ensure an empty key if master token is not set.
        # This avoids HTTP 400.
        header_token = self.master_token or ""
        body = {
            "oldSessionToken": self.token,
            "requestType": request_type,
        }
        ret = await self._post_request(
            url,
            headers,
            json.dumps(body, cls=SnowflakeRestfulJsonEncoder),
            token=header_token,
        )
        if ret.get("success") and ret.get("data", {}).get("sessionToken"):
            logger.debug("success: %s", SecretDetector.mask_secrets(str(ret)))
            await self.update_tokens(
                ret["data"]["sessionToken"],
                ret["data"].get("masterToken"),
                master_validity_in_seconds=ret["data"].get("masterValidityInSeconds"),
            )
            logger.debug("updating session completed")
            return ret
        else:
            logger.debug("failed: %s", SecretDetector.mask_secrets(str(ret)))
            err = ret.get("message")
            if err is not None and ret.get("data"):
                err += ret["data"].get("errorMessage", "")
            errno = ret.get("code") or ER_FAILED_TO_RENEW_SESSION
            if errno in (
                ID_TOKEN_EXPIRED_GS_CODE,
                SESSION_EXPIRED_GS_CODE,
                MASTER_TOKEN_NOTFOUND_GS_CODE,
                MASTER_TOKEN_EXPIRED_GS_CODE,
                MASTER_TOKEN_INVALD_GS_CODE,
                BAD_REQUEST_GS_CODE,
            ):
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=err,
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    )
                )
            Error.errorhandler_wrapper(
                self._connection,
                None,
                ProgrammingError,
                {
                    "msg": err,
                    "errno": int(errno),
                    "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                },
            )

    async def _heartbeat(self) -> Any | dict[Any, Any] | None:
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        request_id = str(uuid.uuid4())
        logger.debug("request_id: %s", request_id)
        url = "/session/heartbeat?" + urlencode({REQUEST_ID: request_id})
        ret = await self._post_request(
            url,
            headers,
            None,
            token=self.token,
        )
        if not ret.get("success"):
            logger.error("Failed to heartbeat. code: %s, url: %s", ret.get("code"), url)
        return ret

    async def delete_session(self, retry: bool = False) -> None:
        """Deletes the session."""
        if self.master_token is None:
            Error.errorhandler_wrapper(
                self._connection,
                None,
                DatabaseError,
                {
                    "msg": "Connection is closed",
                    "errno": ER_CONNECTION_IS_CLOSED,
                    "sqlstate": SQLSTATE_CONNECTION_NOT_EXISTS,
                },
            )

        url = "/session?" + urlencode({"delete": "true"})
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name

        body = {}
        retry_limit = 3 if retry else 1
        num_retries = 0
        should_retry = True
        while should_retry and (num_retries < retry_limit):
            try:
                should_retry = False
                ret = await self._post_request(
                    url,
                    headers,
                    json.dumps(body, cls=SnowflakeRestfulJsonEncoder),
                    token=self.token,
                    timeout=5,
                    no_retry=True,
                )
                if not ret:
                    if retry:
                        should_retry = True
                    else:
                        return
                elif ret.get("success"):
                    return
                err = ret.get("message")
                if err is not None and ret.get("data"):
                    err += ret["data"].get("errorMessage", "")
                    # no exception is raised
                logger.debug("error in deleting session. ignoring...: %s", err)
            except Exception as e:
                logger.debug("error in deleting session. ignoring...: %s", e)
            finally:
                num_retries += 1

    async def _get_request(
        self,
        url: str,
        headers: dict[str, str],
        token: str = None,
        timeout: int | None = None,
        is_fetch_query_status: bool = False,
    ) -> dict[str, Any]:
        if "Content-Encoding" in headers:
            del headers["Content-Encoding"]
        if "Content-Length" in headers:
            del headers["Content-Length"]

        full_url = f"{self.server_url}{url}"
        ret = await self.fetch(
            "get",
            full_url,
            headers,
            timeout=timeout,
            token=token,
            is_fetch_query_status=is_fetch_query_status,
        )
        if ret.get("code") == SESSION_EXPIRED_GS_CODE:
            try:
                ret = await self._renew_session()
            except ReauthenticationRequest as ex:
                if self._connection._authenticator != EXTERNAL_BROWSER_AUTHENTICATOR:
                    raise ex.cause
                ret = await self._connection._reauthenticate()
            logger.debug(
                "ret[code] = {code} after renew_session".format(
                    code=(ret.get("code", "N/A"))
                )
            )
            if ret.get("success"):
                return await self._get_request(
                    url,
                    headers,
                    token=self.token,
                    is_fetch_query_status=is_fetch_query_status,
                )

        return ret

    async def _post_request(
        self,
        url,
        headers,
        body,
        token=None,
        timeout: int | None = None,
        socket_timeout: int | None = None,
        _no_results: bool = False,
        no_retry: bool = False,
        _include_retry_params: bool = False,
    ) -> dict[str, Any]:
        full_url = f"{self.server_url}{url}"
        if self._connection._probe_connection:
            # TODO: SNOW-1572318 for probe connection
            raise NotImplementedError("probe_connection is not supported in asyncio")

        ret = await self.fetch(
            "post",
            full_url,
            headers,
            data=body,
            timeout=timeout,
            token=token,
            no_retry=no_retry,
            _include_retry_params=_include_retry_params,
            socket_timeout=socket_timeout,
        )
        logger.debug(
            "ret[code] = {code}, after post request".format(
                code=(ret.get("code", "N/A"))
            )
        )

        if ret.get("code") == MASTER_TOKEN_EXPIRED_GS_CODE:
            self._connection.expired = True
        elif ret.get("code") == SESSION_EXPIRED_GS_CODE:
            try:
                ret = await self._renew_session()
            except ReauthenticationRequest as ex:
                if self._connection._authenticator != EXTERNAL_BROWSER_AUTHENTICATOR:
                    raise ex.cause
                ret = await self._connection._reauthenticate()
            logger.debug(
                "ret[code] = {code} after renew_session".format(
                    code=(ret.get("code", "N/A"))
                )
            )
            if ret.get("success"):
                return await self._post_request(
                    url, headers, body, token=self.token, timeout=timeout
                )

        if isinstance(ret.get("data"), dict) and ret["data"].get("queryId"):
            logger.debug("Query id: {}".format(ret["data"]["queryId"]))

        if ret.get("code") == QUERY_IN_PROGRESS_ASYNC_CODE and _no_results:
            return ret

        while ret.get("code") in (QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE):
            if self._inject_client_pause > 0:
                logger.debug("waiting for %s...", self._inject_client_pause)
                await asyncio.sleep(self._inject_client_pause)
            # ping pong
            result_url = ret["data"]["getResultUrl"]
            logger.debug("ping pong starting...")
            ret = await self._get_request(
                result_url,
                headers,
                token=self.token,
                timeout=timeout,
                is_fetch_query_status=bool(
                    re.match(r"^/queries/.+/result$", result_url)
                ),
            )
            logger.debug("ret[code] = %s", ret.get("code", "N/A"))
            logger.debug("ping pong done")

        return ret

    async def fetch(
        self,
        method: str,
        full_url: str,
        headers: dict[str, Any],
        data: dict[str, Any] | None = None,
        timeout: int | None = None,
        **kwargs,
    ) -> dict[Any, Any]:
        """Carry out API request with session management."""

        class RetryCtx(TimeoutBackoffCtx):
            def __init__(
                self,
                _include_retry_params: bool = False,
                _include_retry_reason: bool = False,
                **kwargs,
            ) -> None:
                super().__init__(**kwargs)
                self.retry_reason = 0
                self._include_retry_params = _include_retry_params
                self._include_retry_reason = _include_retry_reason

            def add_retry_params(self, full_url: str) -> str:
                if self._include_retry_params and self.current_retry_count > 0:
                    retry_params = {
                        "clientStartTime": self._start_time_millis,
                        "retryCount": self.current_retry_count,
                    }
                    if self._include_retry_reason:
                        retry_params.update({"retryReason": self.retry_reason})
                    suffix = urlencode(retry_params)
                    sep = "&" if urlparse(full_url).query else "?"
                    return full_url + sep + suffix
                else:
                    return full_url

        include_retry_reason = self._connection._enable_retry_reason_in_query_response
        include_retry_params = kwargs.pop("_include_retry_params", False)

        async with self.use_session(full_url) as session:
            retry_ctx = RetryCtx(
                _include_retry_params=include_retry_params,
                _include_retry_reason=include_retry_reason,
                timeout=(
                    timeout if timeout is not None else self._connection.network_timeout
                ),
                backoff_generator=self._connection._backoff_generator,
            )

            retry_ctx.set_start_time()
            while True:
                ret = await self._request_exec_wrapper(
                    session, method, full_url, headers, data, retry_ctx, **kwargs
                )
                if ret is not None:
                    return ret

    async def _request_exec_wrapper(
        self,
        session,
        method,
        full_url,
        headers,
        data,
        retry_ctx,
        no_retry: bool = False,
        token=NO_TOKEN,
        **kwargs,
    ):
        conn = self._connection
        logger.debug(
            "remaining request timeout: %s ms, retry cnt: %s",
            retry_ctx.remaining_time_millis if retry_ctx.timeout is not None else "N/A",
            retry_ctx.current_retry_count + 1,
        )

        full_url = retry_ctx.add_retry_params(full_url)
        full_url = SnowflakeRestful.add_request_guid(full_url)
        is_fetch_query_status = kwargs.pop("is_fetch_query_status", False)
        try:
            return_object = await self._request_exec(
                session=session,
                method=method,
                full_url=full_url,
                headers=headers,
                data=data,
                token=token,
                **kwargs,
            )
            if return_object is not None:
                return return_object
            if is_fetch_query_status:
                err_msg = (
                    "fetch query status failed and http request returned None, this"
                    " is usually caused by transient network failures, retrying..."
                )
                logger.info(err_msg)
                raise RetryRequest(err_msg)
            self._handle_unknown_error(method, full_url, headers, data, conn)
            return {}
        except RevocationCheckError as rce:
            rce.exception_telemetry(rce.msg, None, self._connection)
            raise rce
        except RetryRequest as e:
            cause = e.args[0]
            if no_retry:
                self.log_and_handle_http_error_with_cause(
                    e,
                    full_url,
                    method,
                    retry_ctx.timeout,
                    retry_ctx.current_retry_count,
                    conn,
                    timed_out=False,
                )
                return {}  # required for tests
            if not retry_ctx.should_retry:
                self.log_and_handle_http_error_with_cause(
                    e,
                    full_url,
                    method,
                    retry_ctx.timeout,
                    retry_ctx.current_retry_count,
                    conn,
                )
                return {}  # required for tests

            logger.debug(
                "retrying: errorclass=%s, "
                "error=%s, "
                "counter=%s, "
                "sleeping=%s(s)",
                type(cause),
                cause,
                retry_ctx.current_retry_count + 1,
                retry_ctx.current_sleep_time,
            )
            await asyncio.sleep(float(retry_ctx.current_sleep_time))
            retry_ctx.increment()

            reason = getattr(cause, "errno", 0)
            if reason is None:
                reason = 0
            else:
                reason = (
                    reason - ER_HTTP_GENERAL_ERROR
                    if reason >= ER_HTTP_GENERAL_ERROR
                    else reason
                )

            retry_ctx.retry_reason = reason
            # notes: in sync implementation we check ECONNRESET in error message and close low level urllib session
            #  we do not have the logic here because aiohttp handles low level connection close-reopen for us
            return None  # retry
        except Exception as e:
            if not no_retry:
                raise e
            logger.debug("Ignored error", exc_info=True)
            return {}

    async def _request_exec(
        self,
        session: aiohttp.ClientSession,
        method,
        full_url,
        headers,
        data,
        token,
        catch_okta_unauthorized_error: bool = False,
        is_raw_text: bool = False,
        is_raw_binary: bool = False,
        binary_data_handler=None,
        socket_timeout: int | None = None,
        is_okta_authentication: bool = False,
    ):
        if socket_timeout is None:
            if self._connection.socket_timeout is not None:
                logger.debug("socket_timeout specified in connection")
                socket_timeout = self._connection.socket_timeout
            else:
                socket_timeout = DEFAULT_SOCKET_CONNECT_TIMEOUT
        logger.debug("socket timeout: %s", socket_timeout)

        try:
            if not catch_okta_unauthorized_error and data and len(data) > 0:
                headers["Content-Encoding"] = "gzip"
                input_data = gzip.compress(data.encode("utf-8"))
            else:
                input_data = data

            if HEADER_AUTHORIZATION_KEY in headers:
                del headers[HEADER_AUTHORIZATION_KEY]
            if token != NO_TOKEN:
                headers[HEADER_AUTHORIZATION_KEY] = HEADER_SNOWFLAKE_TOKEN.format(
                    token=token
                )

            # socket timeout is constant. You should be able to receive
            # the response within the time. If not, asyncio.TimeoutError is raised.

            # delta compared to sync:
            #  - in sync, we specify "verify" to True; in aiohttp,
            #  the counter parameter is "ssl" and it already defaults to True
            raw_ret = await session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=input_data,
                timeout=aiohttp.ClientTimeout(socket_timeout),
            )
            try:
                if raw_ret.status == OK:
                    logger.debug("SUCCESS")
                    if is_raw_text:
                        ret = await raw_ret.text()
                    elif is_raw_binary:
                        # TODO: SNOW-1738595 for is_raw_binary support
                        raise NotImplementedError(
                            "reading raw binary data is not supported in asyncio connector,"
                            " please open a feature request issue in"
                            " github: https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose"
                        )
                    else:
                        ret = await raw_ret.json()
                    return ret

                if is_login_request(full_url) and raw_ret.status == FORBIDDEN:
                    raise ForbiddenError

                elif is_retryable_http_code(raw_ret.status):
                    err = get_http_retryable_error(raw_ret.status)
                    # retryable server exceptions
                    if is_okta_authentication:
                        raise RefreshTokenError(
                            msg="OKTA authentication requires token refresh."
                        )
                    if is_login_request(full_url):
                        logger.debug(
                            "Received retryable response code while logging in. Will be handled by "
                            f"authenticator. Ignore the following. Error stack: {err}",
                            exc_info=True,
                        )
                        raise OperationalError(
                            msg="Login request is retryable. Will be handled by authenticator",
                            errno=ER_RETRYABLE_CODE,
                        )
                    else:
                        logger.debug(f"{err}. Retrying...")
                        raise RetryRequest(err)

                elif raw_ret.status == UNAUTHORIZED and catch_okta_unauthorized_error:
                    # OKTA Unauthorized errors
                    raise_okta_unauthorized_error(self._connection, raw_ret)
                    return None  # required for tests
                else:
                    raise_failed_request_error(
                        self._connection, full_url, method, raw_ret
                    )
                    return None  # required for tests
            finally:
                raw_ret.close()  # ensure response is closed
        except (aiohttp.ClientSSLError, aiohttp.ClientConnectorSSLError) as se:
            if is_econnreset_exception(se):
                raise RetryRequest(se.os_error)
            msg = f"Hit non-retryable SSL error, {str(se)}.\n{_CONNECTIVITY_ERR_MSG}"
            logger.debug(msg)
            # the following code is for backward compatibility with old versions of python connector which calls
            # self._handle_unknown_error to process SSLError
            Error.errorhandler_wrapper(
                self._connection,
                None,
                OperationalError,
                {
                    "msg": msg,
                    "errno": ER_FAILED_TO_REQUEST,
                },
            )
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientConnectorError,
            aiohttp.ConnectionTimeoutError,
            asyncio.TimeoutError,
            OpenSSL.SSL.SysCallError,
            KeyError,  # SNOW-39175: asn1crypto.keys.PublicKeyInfo
            ValueError,
            RuntimeError,
            AttributeError,  # json decoding error
        ) as err:
            if isinstance(err, RuntimeError) and "Event loop is closed" in str(err):
                logger.info(
                    "If you see the logging error message 'RuntimeError: Event loop is closed' during program exit, it probably indicates that the connection was not closed properly before the event loop was shut down. Please use SnowflakeConnection.close() to close connection."
                )
                raise err
            if is_login_request(full_url):
                logger.debug(
                    "Hit a timeout error while logging in. Will be handled by "
                    f"authenticator. Ignore the following. Error stack: {err}",
                    exc_info=True,
                )
                raise OperationalError(
                    msg="ConnectionTimeout occurred during login. Will be handled by authenticator",
                    errno=ER_CONNECTION_TIMEOUT,
                )
            else:
                logger.debug(
                    "Hit retryable client error. Retrying... Ignore the following "
                    f"error stack: {err}",
                    exc_info=True,
                )
                raise RetryRequest(err)
        except Exception as err:
            if isinstance(err, (Error, RetryRequest, ReauthenticationRequest)):
                raise err
            raise OperationalError(
                msg=f"Unexpected error occurred during request execution: {err}"
                "Please check the stack trace for more information and retry the operation."
                "If you think this is a bug, please collect the error information and open a bug report in github: "
                "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose.",
                errno=ER_FAILED_TO_REQUEST,
            ) from err

    @contextlib.asynccontextmanager
    async def use_session(
        self, url: str | None = None
    ) -> AsyncGenerator[aiohttp.ClientSession]:
        async with self._session_manager.use_session(url) as session:
            yield session
