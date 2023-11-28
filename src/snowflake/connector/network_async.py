#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import nest_asyncio
import aiohttp

from .network import *

# YICHUAN: If a user calls any of our  methods from their async code, when we try to call loop.run_until_complete
# it will raise "RuntimeError: This event loop is already running"
def run_until_complete_safe(loop, coro) -> Any:
    if loop.is_running():
        # YICHUAN: Patching a loop multiple times is safe
        nest_asyncio.apply(loop)
    return loop.run_until_complete(coro)

# YICHUAN: If we don't want to duplicate these raise  functions we can also modify them to directly take the error
# status and reason instead of a response object (that way we can use the same for both sync and async)
# For this commit I'm just adding separate functions for async so that I don't need to change too much code
def raise_okta_unauthorized_error_async(
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


def raise_failed_request_error_async(
    connection: SnowflakeConnection | None,
    url: str,
    method: str,
    response: aiohttp.ClientResponse,
) -> None:
    # YICHUAN: NO TELEMETRY FOR NOW

    # TelemetryService.get_instance().log_http_request_error(
    #     f"HttpError{response.status}",
    #     url,
    #     method,
    #     SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
    #     ER_FAILED_TO_REQUEST,
    #     response=response,
    # )
    Error.errorhandler_wrapper(
        connection,
        None,
        InterfaceError,
        {
            "msg": f"{response.status} {response.reason}: {method} {url}",
            "errno": ER_FAILED_TO_REQUEST,
            "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
        },
    )


# Yichuan: CURRENTLY UNUSED, see SnowflakeRestfulAsync._request_exec_async
class SnowflakeAuthAsync(aiohttp.BasicAuth):
    def __new__(cls, token: str) -> aiohttp.BasicAuth:
        # for class compatibility with BasicAuth, these parameters are never used
        return super().__new__(cls, "", "", "")

    def __init__(self, token: str) -> None:
        self.token = token

    def encode(self) -> str:
        """aiohttp will use this to set the Authorization header"""
        return HEADER_SNOWFLAKE_TOKEN.format(token=self.token)


class SessionPoolAsync(SessionPool):
    async def close_async(self) -> None:
        """Closes all active and idle sessions in this session pool."""
        if self._active_sessions:
            logger.debug(f"Closing {len(self._active_sessions)} active sessions")
        for s in itertools.chain(self._active_sessions, self._idle_sessions):
            try:
                await s.close()
            except Exception as e:
                logger.info(f"Session cleanup failed: {e}")
        self._active_sessions.clear()
        self._idle_sessions.clear()


class SnowflakeRestfulAsync(SnowflakeRestful):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        protocol: str = "http",
        inject_client_pause: int = 0,
        connection: SnowflakeConnection | None = None,
    ) -> None:
        self._loop = asyncio.get_event_loop()

        self._host = host
        self._port = port
        self._protocol = protocol
        self._inject_client_pause = inject_client_pause
        self._connection = connection
        self._lock_token = Lock()
        self._sessions_map: dict[
            str | None, SessionPoolAsync
        ] = collections.defaultdict(lambda: SessionPoolAsync(self))

        # OCSP mode (OCSPMode.FAIL_OPEN by default)
        ssl_wrap_socket.FEATURE_OCSP_MODE = (
            self._connection._ocsp_mode()
            if self._connection
            else ssl_wrap_socket.DEFAULT_OCSP_MODE
        )
        # cache file name (enabled by default)
        ssl_wrap_socket.FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = (
            self._connection._ocsp_response_cache_filename if self._connection else None
        )

        # This is to address the issue where requests hangs
        _ = "dummy".encode("idna").decode("utf-8")

    def close(self) -> None:
        if hasattr(self, "_token"):
            del self._token
        if hasattr(self, "_master_token"):
            del self._master_token
        if hasattr(self, "_id_token"):
            del self._id_token
        if hasattr(self, "_mfa_token"):
            del self._mfa_token

        # self._loop.run_until_complete(self.close_async())
        run_until_complete_safe(self._loop, self.close_async())
        # YICHUAN: We do not need to close the loop ourselves (in fact we should not because the client might own it)
        # self._loop.close()

    async def close_async(self) -> None:
        for session_pool in self._sessions_map.values():
            await session_pool.close_async()

    def fetch(self, *args, **kwargs) -> dict[Any, Any]:
        # return self._loop.run_until_complete(self.fetch_async(*args, **kwargs))
        return run_until_complete_safe(self._loop, self.fetch_async(*args, **kwargs))

    async def fetch_async(
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

        async with self._use_requests_session_async(full_url) as session:
            retry_ctx = RetryCtx(
                _include_retry_params=include_retry_params,
                _include_retry_reason=include_retry_reason,
                timeout=timeout
                if timeout is not None
                else self._connection.network_timeout,
                backoff_generator=self._connection._backoff_generator,
            )

            retry_ctx.set_start_time()
            while True:
                ret = await self._request_exec_wrapper_async(
                    session, method, full_url, headers, data, retry_ctx, **kwargs
                )
                if ret is not None:
                    return ret

    async def _request_exec_wrapper_async(
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
        try:
            return_object = await self._request_exec_async(
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
            self._handle_unknown_error(method, full_url, headers, data, conn)
            TelemetryService.get_instance().log_http_request_error(
                "HttpRequestUnknownError",
                full_url,
                method,
                SQLSTATE_IO_ERROR,
                ER_FAILED_TO_REQUEST,
                retry_timeout=retry_ctx.timeout,
                retry_count=retry_ctx.current_retry_count,
            )
            return {}
        except RetryRequest as e:
            if (
                retry_ctx.current_retry_count
                == TelemetryService.get_instance().num_of_retry_to_trigger_telemetry
            ):
                TelemetryService.get_instance().log_http_request_error(
                    "HttpRequestRetry%dTimes" % retry_ctx.current_retry_count,
                    full_url,
                    method,
                    SQLSTATE_IO_ERROR,
                    ER_FAILED_TO_REQUEST,
                    retry_timeout=retry_ctx.timeout,
                    retry_count=retry_ctx.current_retry_count,
                    exception=str(e),
                    stack_trace=traceback.format_exc(),
                )
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
            # YICHUAN: Async might change how we want to  calculate timeouts; instead of {current time} - {start time}
            # we should consider tracking the time spent sleeping, because a coroutine might spend excessive time
            # waiting for control to be given back to it by the event loop
            await asyncio.sleep(float(retry_ctx.current_sleep_time))
            retry_ctx.increment()

            reason = getattr(cause, "errno", 0)
            retry_ctx.retry_reason = reason

            # YICHUAN: aiohttp doesn't provide a convenient method like session.get_adapter to close an adapter if we
            # receive "Connection aborted" or "ECONNRESET"; aiohttp tends to release the connection itself on success
            # receiving EOF, or close the connection itself if something went wrong
            # (If you want to see for yourself, look at aiohttp.ClientResponse._response_eof)
            # This means that we can't access the connection used to close it without calling internal methods, which
            # is dangerous if it was acquired concurrently before the control flow reaches here
            # Not checking for "Connection aborted" or "ECONNRESET" shouldn't cause any problems as aiohttp rebuilds
            # broken connections the next time it's used anyway, but we can subclass ClientSession to override _request
            # if we really want to add the check, at the cost of a lot more code

            return None  # retry
        except Exception as e:
            if not no_retry:
                raise e
            logger.debug("Ignored error", exc_info=True)
            return {}

    async def _request_exec_async(
        self,
        session,
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
        if is_raw_binary or binary_data_handler is not None:
            raise Exception(
                "YICHUAN: Placeholder check, this should never happen in async code path"
            )

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

            # YICHUAN: Adding auth headers here isn't ideal (though I've checked that they won't be overriden)
            # If we want to pass an auth mechanism to request instead we can pass in auth=SnowflakeAuthAsync, but we
            # have to do some hacky stuff with the class to make it play nice with aiohttp.BasicAuth
            if HEADER_AUTHORIZATION_KEY in headers:
                del headers[HEADER_AUTHORIZATION_KEY]
            if token != NO_TOKEN:
                headers[HEADER_AUTHORIZATION_KEY] = HEADER_SNOWFLAKE_TOKEN.format(
                    token=token
                )

            # Yichuan: No need to track these as aiohttp doesn't have is_raw_binary

            # download_start_time = get_time_millis()

            resp = await session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=input_data,
                proxy=None,
                # Yichuan: Should be fine specifying this unconditionally as proxy_headers will be ignored if no proxy
                # is specified in env variables
                # (If you want to see for yourself, check that proxy_headers are only used to set the attribute
                # ClientRequest.proxy_headers, which are in turn only used in TCPConnector._create_proxy_connection)
                proxy_headers={"Host": parse_url(full_url).hostname},
                ssl=None,  # Yichuan: Default SSL check, replace later
            )

            # download_end_time = get_time_millis()

            try:
                if resp.status == OK:
                    logger.debug("SUCCESS")
                    if is_raw_text:
                        ret = await resp.text()
                    else:
                        ret = await resp.json()
                    return ret

                if is_login_request(full_url) and resp.status == FORBIDDEN:
                    raise ForbiddenError

                elif is_retryable_http_code(resp.status):
                    err = get_http_retryable_error(resp.status)
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

                elif resp.status == UNAUTHORIZED and catch_okta_unauthorized_error:
                    # OKTA Unauthorized errors
                    raise_okta_unauthorized_error_async(self._connection, resp)
                    return None  # required for tests
                else:
                    raise_failed_request_error_async(
                        self._connection, full_url, method, resp
                    )
                    return None  # required for tests
            finally:
                # YICHUAN: aiohttp releases the connection at the end of the request; we don't need to
                # (I'll remove this redundant block when cleaning up the code later, this is here for clarity)
                pass
        except aiohttp.ClientSSLError as se:
            logger.debug("Hit non-retryable SSL error, %s", str(se))
            TelemetryService.get_instance().log_http_request_error(
                "CertificateException%s" % str(se),
                full_url,
                method,
                SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                ER_FAILED_TO_REQUEST,
                exception=se,
                stack_trace=traceback.format_exc(),
            )

        # YICHUAN: The requests caught here are tentative, I have likely missed some and will add more in with as I
        # test more types of requests
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientPayloadError,
            aiohttp.ClientResponseError,
            aiohttp.ServerTimeoutError,
            IncompleteRead,
            OpenSSL.SSL.SysCallError,
            KeyError,  # SNOW-39175: asn1crypto.keys.PublicKeyInfo
            ValueError,
            RuntimeError,
            AttributeError,  # json decoding error
        ) as err:
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
            TelemetryService.get_instance().log_http_request_error(
                "HttpException%s" % str(err),
                full_url,
                method,
                SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                ER_FAILED_TO_REQUEST,
                exception=err,
                stack_trace=traceback.format_exc(),
            )
            raise err

    # Yichuan: Override method, not _async because it's not an async method
    def make_requests_session(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            auth=None,  # Yichuan: auth=None so auth headers aren't overriden inside ClientSession requests
            trust_env=True,  # Yichuan: So aiohttp will read the proxy variables set in proxy.set_proxies
            loop=self._loop,
        )

    # Yichuan: Literally copy & pasted but unfortunately needed because this method needs to be async

    # Q for later: Why do we need to pool sessions when sessions already pool connections for different hosts?
    @contextlib.asynccontextmanager
    async def _use_requests_session_async(self, url: str | None = None):
        """Session caching context manager."""

        # short-lived session, not added to the _sessions_map
        if self._connection.disable_request_pooling:
            session = self.make_requests_session()
            try:
                yield session
            finally:
                await session.close()
        else:
            try:
                hostname = urlparse(url).hostname
            except Exception:
                hostname = None

            session_pool: SessionPoolAsync = self._sessions_map[hostname]
            session = session_pool.get_session()
            logger.debug(
                f"Session status for SessionPoolAsync '{hostname}', {session_pool}"
            )
            try:
                yield session
            finally:
                session_pool.return_session(session)
                logger.debug(
                    f"Session status for SessionPoolAsync '{hostname}', {session_pool}"
                )
