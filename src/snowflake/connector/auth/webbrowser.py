#!/usr/bin/env python
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import select
import socket
import time
import webbrowser
from types import ModuleType
from typing import TYPE_CHECKING, Any

from ..compat import IS_WINDOWS, parse_qs, urlencode, urlparse, urlsplit
from ..constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from ..errorcode import (
    ER_INVALID_VALUE,
    ER_NO_HOSTNAME_FOUND,
    ER_UNABLE_TO_OPEN_BROWSER,
)
from ..errors import OperationalError
from ..network import (
    CONTENT_TYPE_APPLICATION_JSON,
    EXTERNAL_BROWSER_AUTHENTICATOR,
    PYTHON_CONNECTOR_USER_AGENT,
)
from ..url_util import is_valid_url
from . import Auth
from .by_plugin import AuthByPlugin, AuthType

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)

BUF_SIZE = 16384


# global state of web server that receives the SAML assertion from
# Snowflake server


class AuthByWebBrowser(AuthByPlugin):
    """Authenticates user by web browser. Only used for SAML based authentication."""

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
        super().__init__(**kwargs)
        self.consent_cache_id_token = True
        self._token: str | None = None
        self._application = application
        self._proof_key = None
        self._webbrowser: ModuleType = (
            webbrowser if webbrowser_pkg is None else webbrowser_pkg
        )
        self._socket: type[socket.socket] = (
            socket.socket if socket_pkg is None else socket_pkg
        )
        self._protocol = protocol
        self._host = host
        self._port = port
        self._origin = None

    def reset_secrets(self) -> None:
        self._token = None

    @property
    def type_(self) -> AuthType:
        return AuthType.EXTERNAL_BROWSER

    @property
    def assertion_content(self) -> str:
        """Returns the token."""
        return self._token

    def update_body(self, body: dict[Any, Any]) -> None:
        """Used by Auth to update the request that gets sent to /v1/login-request.

        Args:
            body: existing request dictionary
        """
        body["data"]["AUTHENTICATOR"] = EXTERNAL_BROWSER_AUTHENTICATOR
        body["data"]["TOKEN"] = self._token
        body["data"]["PROOF_KEY"] = self._proof_key

    def prepare(
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

        # TODO: switch to the new AuthHttpServer class instead of doing this manually
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
            socket_connection.listen(5)
            callback_port = socket_connection.getsockname()[1]

            if conn._disable_console_login:
                logger.debug("step 1: query GS to obtain SSO url")
                sso_url = self._get_sso_url(
                    conn, authenticator, service_name, account, callback_port, user
                )
            else:
                logger.debug("step 1: constructing console login url")
                sso_url = self._get_console_login_url(conn, callback_port, user)

            logger.debug("Validate SSO URL")
            if not is_valid_url(sso_url):
                self._handle_failure(
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
                self._receive_saml_token(conn, socket_connection)
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
                    self._handle_failure(
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

    def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        conn.authenticate_with_retry(self)
        return {"success": True}

    def _receive_saml_token(self, conn: SnowflakeConnection, socket_connection) -> None:
        """Receives SAML token from web browser."""
        while True:
            try:
                attempts = 0
                raw_data = bytearray()
                socket_client = None
                max_attempts = 15

                msg_dont_wait = (
                    os.getenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "false").lower()
                    == "true"
                )
                if IS_WINDOWS:
                    if msg_dont_wait:
                        logger.warning(
                            "Configuration SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT is not available in Windows. Ignoring."
                        )
                    msg_dont_wait = False

                # when running in a containerized environment, socket_client.recv ocassionally returns an empty byte array
                #   an immediate successive call to socket_client.recv gets the actual data
                while len(raw_data) == 0 and attempts < max_attempts:
                    attempts += 1
                    read_sockets, _write_sockets, _exception_sockets = select.select(
                        [socket_connection], [], []
                    )

                    if read_sockets[0] is not None:
                        # Receive the data in small chunks and retransmit it
                        socket_client, _ = socket_connection.accept()

                        try:
                            if msg_dont_wait:
                                # WSL containerized environment sometimes causes socket_client.recv to hang indefinetly
                                #   To avoid this, passing the socket.MSG_DONTWAIT flag which raises BlockingIOError if
                                #   operation would block
                                logger.debug(
                                    "Calling socket_client.recv with MSG_DONTWAIT flag due to SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT env var"
                                )
                                raw_data = socket_client.recv(
                                    BUF_SIZE, socket.MSG_DONTWAIT
                                )
                            else:
                                raw_data = socket_client.recv(BUF_SIZE)

                        except BlockingIOError:
                            logger.debug(
                                "BlockingIOError raised from socket.recv while attempting to retrieve callback token request"
                            )
                            if attempts < max_attempts:
                                sleep_time = 0.25
                                logger.debug(
                                    f"Waiting {sleep_time} seconds before trying again"
                                )
                                time.sleep(sleep_time)
                            else:
                                logger.debug("Exceeded retry count")

                if not raw_data:
                    continue

                data = raw_data.decode("utf-8").splitlines()

                method = self._request_method(data)
                if method == "OPTIONS":
                    self._process_options(data, socket_client)
                    continue
                if method not in {"GET", "POST"}:
                    continue
                if not self._validate_callback_origin(data):
                    continue
                if self._process_receive_saml_token(conn, data, socket_client):
                    break

            finally:
                self._close_socket_client(socket_client)

    def _process_options(self, data: list[str], socket_client: socket.socket) -> bool:
        """Allows JS Ajax access to this endpoint."""
        if self._request_method(data) != "OPTIONS":
            return False

        self._get_user_agent(data)
        requested_headers, requested_origin = self._check_post_requested(data)
        if requested_origin is None:
            return True

        if requested_headers and any(
            header.strip().lower() != "content-type"
            for header in requested_headers.split(",")
        ):
            return True

        if not self._validate_origin(requested_origin):
            return True

        self._origin = requested_origin
        content = [
            "HTTP/1.1 200 OK",
            "Date: {}".format(
                time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            ),
            "Access-Control-Allow-Methods: POST",
            "Access-Control-Allow-Headers: Content-Type",
            "Access-Control-Max-Age: 86400",
            f"Access-Control-Allow-Origin: {self._origin}",
            "",
            "",
        ]
        socket_client.sendall("\r\n".join(content).encode("utf-8"))
        return True

    def _validate_origin(self, requested_origin: str) -> bool:
        try:
            parsed = urlsplit(requested_origin)
            expected_scheme = (self._protocol or "").lower()
            expected_port = (
                int(self._port)
                if self._port is not None
                else self._default_port(expected_scheme)
            )
            actual_port = parsed.port or self._default_port(parsed.scheme.lower())
        except (TypeError, ValueError):
            return False

        return (
            parsed.scheme.lower() == expected_scheme
            and parsed.hostname is not None
            and parsed.hostname.lower() == (self._host or "").lower()
            and actual_port == expected_port
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )

    @staticmethod
    def _default_port(protocol: str) -> int | None:
        if protocol == "https":
            return 443
        if protocol == "http":
            return 80
        return None

    @staticmethod
    def _header_lines(data: list[str]) -> list[str]:
        try:
            return data[: data.index("")]
        except ValueError:
            return data

    @classmethod
    def _request_method(cls, data: list[str]) -> str | None:
        header_lines = cls._header_lines(data)
        if not header_lines:
            return None
        parts = header_lines[0].split(maxsplit=1)
        return parts[0].upper() if parts else None

    @classmethod
    def _request_body(cls, data: list[str]) -> str | None:
        try:
            separator = data.index("")
        except ValueError:
            return None
        return "\n".join(data[separator + 1 :])

    @classmethod
    def _get_header(cls, data: list[str], name: str) -> str | None:
        prefix = name.lower() + ":"
        for line in cls._header_lines(data)[1:]:
            if line.lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
        return None

    def _validate_callback_origin(self, data: list[str]) -> bool:
        method = self._request_method(data)
        if method not in {"GET", "POST"}:
            self._origin = None
            return False
        requested_origin = self._get_header(data, "Origin")
        if method == "GET" and (
            requested_origin is None or requested_origin.lower() == "null"
        ):
            self._origin = None
            return True
        if requested_origin is None or not self._validate_origin(requested_origin):
            return False
        self._origin = requested_origin
        return True

    @staticmethod
    def _close_socket_client(socket_client: socket.socket | None) -> None:
        if socket_client is None:
            return
        try:
            socket_client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            socket_client.close()
        except OSError:
            pass

    def _process_receive_saml_token(
        self, conn: SnowflakeConnection, data: list[str], socket_client: socket.socket
    ) -> bool:
        if not self._process_get(data) and not self._process_post(conn, data):
            return False

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

        socket_client.sendall("\r\n".join(content).encode("utf-8"))
        return True

    def _check_post_requested(self, data: list[str]) -> tuple[str | None, str | None]:
        requested_method = self._get_header(data, "Access-Control-Request-Method")
        requested_origin = self._get_header(data, "Origin")
        if (
            requested_method is None
            or requested_origin is None
            or requested_method.upper() != "POST"
        ):
            return None, None

        return (
            self._get_header(data, "Access-Control-Request-Headers") or "",
            requested_origin,
        )

    def _process_get_url(self, url: str) -> bool:
        parsed = parse_qs(urlparse(url).query)
        if "token" not in parsed or not parsed["token"][0]:
            return False
        self._token = parsed["token"][0]
        return True

    def _process_get(self, data: list[str]) -> bool:
        header_lines = self._header_lines(data)
        if self._request_method(data) != "GET" or not header_lines:
            return False

        self._get_user_agent(data)
        try:
            _, url, _ = header_lines[0].split()
        except ValueError:
            return False
        return self._process_get_url(url)

    def _process_post(self, conn: SnowflakeConnection, data: list[str]) -> bool:
        body = self._request_body(data)
        if self._request_method(data) != "POST" or body is None:
            return False

        self._get_user_agent(data)
        try:
            # parse the response as JSON
            payload = json.loads(body)
            self._token = payload.get("token")
            self.consent_cache_id_token = payload.get("consent", True)
        except Exception:
            # key=value form.
            self._token = (parse_qs(body).get("token") or [None])[0]
        return self._token is not None

    def _get_user_agent(self, data: list[str]) -> None:
        for line in self._header_lines(data):
            if line.lower().startswith("user-agent"):
                logger.debug(line)
                break
        else:
            logger.debug("No User-Agent")

    def _get_sso_url(
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
            session_manager=conn.rest.session_manager.clone(use_pooling=False),
        )

        body["data"]["AUTHENTICATOR"] = authenticator
        body["data"]["BROWSER_MODE_REDIRECT_PORT"] = str(callback_port)
        logger.debug(
            "account=%s, authenticator=%s, user=%s", account, authenticator, user
        )
        ret = conn._rest._post_request(
            url,
            headers,
            json.dumps(body),
            timeout=conn._rest._connection.login_timeout,
            socket_timeout=conn._rest._connection.login_timeout,
        )
        if not ret["success"]:
            self._handle_failure(conn=conn, ret=ret)
        data = ret["data"]
        sso_url = data["ssoUrl"]
        self._proof_key = data["proofKey"]
        return sso_url

    def _get_console_login_url(
        self, conn: SnowflakeConnection, port: int, user: str
    ) -> str:
        self._proof_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        url = (
            conn._rest.server_url
            + "/console/login?"
            + urlencode(
                {
                    "login_name": user,
                    "browser_mode_redirect_port": port,
                    "proof_key": self._proof_key,
                }
            )
        )
        logger.debug(f"Console Log In URL: {url}")
        return url
