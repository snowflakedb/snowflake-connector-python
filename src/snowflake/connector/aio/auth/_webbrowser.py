#!/usr/bin/env python

from __future__ import annotations

import asyncio
import json
import logging
import os
import select
import socket
import time
from types import ModuleType
from typing import TYPE_CHECKING, Any

from snowflake.connector.aio.auth import Auth

from ... import OperationalError
from ...auth.webbrowser import BUF_SIZE
from ...auth.webbrowser import AuthByWebBrowser as AuthByWebBrowserSync
from ...compat import IS_WINDOWS, parse_qs
from ...constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from ...errorcode import (
    ER_IDP_CONNECTION_ERROR,
    ER_INVALID_VALUE,
    ER_NO_HOSTNAME_FOUND,
    ER_UNABLE_TO_OPEN_BROWSER,
)
from ...network import (
    CONTENT_TYPE_APPLICATION_JSON,
    DEFAULT_SOCKET_CONNECT_TIMEOUT,
    PYTHON_CONNECTOR_USER_AGENT,
)
from ...url_util import is_valid_url
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

if TYPE_CHECKING:
    from .._connection import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByWebBrowser(AuthByPluginAsync, AuthByWebBrowserSync):
    def __init__(
        self,
        application: str,
        webbrowser_pkg: ModuleType | None = None,
        socket_pkg: type[socket.socket] | None = None,
        protocol: str | None = None,
        host: str | None = None,
        port: str | None = None,
        **kwargs,
    ) -> None:
        AuthByWebBrowserSync.__init__(
            self,
            application,
            webbrowser_pkg,
            socket_pkg,
            protocol,
            host,
            port,
            **kwargs,
        )
        self._event_loop = asyncio.get_event_loop()

    async def reset_secrets(self) -> None:
        AuthByWebBrowserSync.reset_secrets(self)

    async def prepare(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> None:
        """Web Browser based Authentication."""
        logger.debug("authenticating by Web Browser")

        socket_connection = self._socket(socket.AF_INET, socket.SOCK_STREAM)

        if os.getenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "False").lower() == "true":
            if IS_WINDOWS:
                logger.warning(
                    "Configuration SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not available in Windows. Ignoring."
                )
            else:
                socket_connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        try:
            hostname = os.getenv("SF_AUTH_SOCKET_ADDR", "localhost")
            try:
                socket_connection.bind(
                    (
                        hostname,
                        int(os.getenv("SF_AUTH_SOCKET_PORT", 0)),
                    )
                )
            except socket.gaierror as ex:
                if ex.args[0] == socket.EAI_NONAME:
                    raise OperationalError(
                        msg=f"{hostname} is not found. Ensure /etc/hosts has "
                        f"{hostname} entry.",
                        errno=ER_NO_HOSTNAME_FOUND,
                    )
                else:
                    raise ex
            socket_connection.listen(0)  # no backlog
            callback_port = socket_connection.getsockname()[1]

            if conn._disable_console_login:
                logger.debug("step 1: query GS to obtain SSO url")
                sso_url = await self._get_sso_url(
                    conn, authenticator, service_name, account, callback_port, user
                )
            else:
                logger.debug("step 1: constructing console login url")
                sso_url = self._get_console_login_url(conn, callback_port, user)

            logger.debug("Validate SSO URL")
            if not is_valid_url(sso_url):
                await self._handle_failure(
                    conn=conn,
                    ret={
                        "code": ER_INVALID_VALUE,
                        "message": (f"The SSO URL provided {sso_url} is invalid"),
                    },
                )
                return

            print(
                "Initiating login request with your identity provider. Press CTRL+C to abort and try again..."
            )

            logger.debug("step 2: open a browser")
            print(f"Going to open: {sso_url} to authenticate...")
            browser_opened = self._webbrowser.open_new(sso_url)
            if browser_opened:
                print(
                    "A browser window should have opened for you to complete the "
                    "login. If you can't see it, check existing browser windows, "
                    "or your OS settings."
                )

            if (
                browser_opened
                or os.getenv("SNOWFLAKE_AUTH_FORCE_SERVER", "False").lower() == "true"
            ):
                logger.debug("step 3: accept SAML token")
                await self._receive_saml_token(conn, socket_connection)
            else:
                print(
                    "We were unable to open a browser window for you, "
                    "please open the url above manually then paste the "
                    "URL you are redirected to into the terminal."
                )
                url = input("Enter the URL the SSO URL redirected you to: ")
                self._process_get_url(url)
                if not self._token:
                    # Input contained no token, either URL was incorrectly pasted,
                    # empty or just wrong
                    await self._handle_failure(
                        conn=conn,
                        ret={
                            "code": ER_UNABLE_TO_OPEN_BROWSER,
                            "message": (
                                "Unable to open a browser in this environment and "
                                "SSO URL contained no token"
                            ),
                        },
                    )
                    return
        finally:
            socket_connection.close()

    async def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        await conn.authenticate_with_retry(self)
        return {"success": True}

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByWebBrowserSync.update_body(self, body)

    async def _receive_saml_token(
        self, conn: SnowflakeConnection, socket_connection
    ) -> None:
        """Receives SAML token from web browser."""
        while True:
            try:
                attempts = 0
                raw_data = bytearray()
                socket_client = None
                max_attempts = 15

                # when running in a containerized environment, socket_client.recv ocassionally returns an empty byte array
                #   an immediate successive call to socket_client.recv gets the actual data
                while len(raw_data) == 0 and attempts < max_attempts:
                    attempts += 1
                    read_sockets, _write_sockets, _exception_sockets = select.select(
                        [socket_connection], [], []
                    )

                    if read_sockets[0] is not None:
                        # Receive the data in small chunks and retransmit it
                        socket_client, _ = await self._event_loop.sock_accept(
                            socket_connection
                        )

                        try:
                            # Async delta: async version of sock_recv does not take flags
                            # on one hand, sock must be a non-blocking socket in async according to python docs:
                            # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.sock_recv
                            # on the other hand according to linux: https://man7.org/linux/man-pages/man2/recvmsg.2.html
                            # sync flag MSG_DONTWAIT achieves the same effect as O_NONBLOCK, but it's a per-call flag
                            # however here for each call we accept a new socket, so they are effectively the same.
                            #  https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.sock_recv
                            socket_client.setblocking(False)
                            raw_data = await asyncio.wait_for(
                                self._event_loop.sock_recv(socket_client, BUF_SIZE),
                                timeout=(
                                    DEFAULT_SOCKET_CONNECT_TIMEOUT
                                    if conn.socket_timeout is None
                                    else conn.socket_timeout
                                ),
                            )
                        except asyncio.TimeoutError:
                            logger.debug(
                                "sock_recv timed out while attempting to retrieve callback token request"
                            )
                            if attempts < max_attempts:
                                sleep_time = 0.25
                                logger.debug(
                                    f"Waiting {sleep_time} seconds before trying again"
                                )
                                await asyncio.sleep(sleep_time)
                            else:
                                logger.debug("Exceeded retry count")

                data = raw_data.decode("utf-8").split("\r\n")

                if not await self._process_options(data, socket_client):
                    await self._process_receive_saml_token(conn, data, socket_client)
                    break

            finally:
                socket_client.shutdown(socket.SHUT_RDWR)
                socket_client.close()

    async def _process_options(
        self, data: list[str], socket_client: socket.socket
    ) -> bool:
        """Allows JS Ajax access to this endpoint."""
        for line in data:
            if line.startswith("OPTIONS "):
                break
        else:
            return False

        self._get_user_agent(data)
        requested_headers, requested_origin = self._check_post_requested(data)
        if not requested_headers:
            return False

        if not self._validate_origin(requested_origin):
            # validate Origin and fail if not match with the server.
            return False

        self._origin = requested_origin
        content = [
            "HTTP/1.1 200 OK",
            "Date: {}".format(
                time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            ),
            "Access-Control-Allow-Methods: POST, GET",
            f"Access-Control-Allow-Headers: {requested_headers}",
            "Access-Control-Max-Age: 86400",
            f"Access-Control-Allow-Origin: {self._origin}",
            "",
            "",
        ]
        await self._event_loop.sock_sendall(
            socket_client, "\r\n".join(content).encode("utf-8")
        )
        return True

    async def _process_receive_saml_token(
        self, conn: SnowflakeConnection, data: list[str], socket_client: socket.socket
    ) -> None:
        if not self._process_get(data) and not await self._process_post(conn, data):
            return  # error

        content = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html",
        ]
        if self._origin:
            data = {"consent": self.consent_cache_id_token}
            msg = json.dumps(data)
            content.append(f"Access-Control-Allow-Origin: {self._origin}")
            content.append("Vary: Accept-Encoding, Origin")
        else:
            msg = f"""
<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<link rel="icon" href="data:,">
<title>SAML Response for Snowflake</title></head>
<body>
Your identity was confirmed and propagated to Snowflake {self._application}.
You can close this window now and go back where you started from.
</body></html>"""
        content.append(f"Content-Length: {len(msg)}")
        content.append("")
        content.append(msg)

        await self._event_loop.sock_sendall(
            socket_client, "\r\n".join(content).encode("utf-8")
        )

    async def _process_post(self, conn: SnowflakeConnection, data: list[str]) -> bool:
        for line in data:
            if line.startswith("POST "):
                break
        else:
            await self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_IDP_CONNECTION_ERROR,
                    "message": "Invalid HTTP request from web browser. Idp "
                    "authentication could have failed.",
                },
            )
            return False

        self._get_user_agent(data)
        try:
            # parse the response as JSON
            payload = json.loads(data[-1])
            self._token = payload.get("token")
            self.consent_cache_id_token = payload.get("consent", True)
        except Exception:
            # key=value form.
            self._token = parse_qs(data[-1])["token"][0]
        return True

    async def _get_sso_url(
        self,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        callback_port: int,
        user: str,
    ) -> str:
        """Gets SSO URL from Snowflake."""
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = service_name

        url = "/session/authenticator-request"
        body = Auth.base_auth_data(
            user,
            account,
            conn.application,
            conn._internal_application_name,
            conn._internal_application_version,
            conn._ocsp_mode(),
            conn.cert_revocation_check_mode,
            conn.login_timeout,
            conn.network_timeout,
            conn.socket_timeout,
            conn.platform_detection_timeout_seconds,
            http_config=conn._session_manager.config,  # AioHttpConfig extends BaseHttpConfig
        )

        body["data"]["AUTHENTICATOR"] = authenticator
        body["data"]["BROWSER_MODE_REDIRECT_PORT"] = str(callback_port)
        logger.debug(
            "account=%s, authenticator=%s, user=%s", account, authenticator, user
        )
        ret = await conn._rest._post_request(
            url,
            headers,
            json.dumps(body),
            timeout=conn.login_timeout,
            socket_timeout=conn.login_timeout,
        )
        if not ret["success"]:
            await self._handle_failure(conn=conn, ret=ret)
        data = ret["data"]
        sso_url = data["ssoUrl"]
        self._proof_key = data["proofKey"]
        return sso_url
