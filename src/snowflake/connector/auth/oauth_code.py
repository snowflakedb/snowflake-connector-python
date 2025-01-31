#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import socket
import time
import urllib.parse
import webbrowser
from typing import TYPE_CHECKING, Any

import urllib3

from ..compat import parse_qs, urlparse, urlsplit
from ..errorcode import (
    ER_IDP_CONNECTION_ERROR,
    ER_OAUTH_STATE_CHANGED,
    ER_UNABLE_TO_OPEN_BROWSER,
)
from ..errors import InterfaceError
from ..network import OAUTH_AUTHENTICATOR
from ._http_server import AuthHttpServer
from .by_plugin import AuthByPlugin, AuthType

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)

BUF_SIZE = 16384


def _get_query_params(
    url: str,
) -> dict[str, list[str]]:
    parsed = parse_qs(urlparse(url).query)
    return parsed


class AuthByOauthCode(AuthByPlugin):
    """Authenticates user by OAuth code flow."""

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str | None,
        authentication_url: str,
        token_request_url: str,
        redirect_uri: str,
        scope: str,
        pkce: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        if "{port}" not in redirect_uri:
            raise InterfaceError("redirect_uri needs '{port}' placeholder for now")
        self._application = application
        self._origin: str | None = None
        self.client_id = client_id
        self.client_secret = client_secret
        self.authentication_url = authentication_url
        self.token_request_url = token_request_url
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._state = secrets.token_urlsafe(43)
        logger.debug("chose oauth state: %s", "".join("*" for _ in self._state))
        self._oauth_token = None
        self._protocol = "http"
        self.pkce = pkce
        if pkce:
            logger.debug("oauth pkce is going to be used")
        self._verifier: str | None = None

    def reset_secrets(self) -> None:
        self._oauth_token = None

    @property
    def type_(self) -> AuthType:
        return AuthType.OAUTH

    @property
    def assertion_content(self) -> str:
        """Returns the token."""
        return self._oauth_token or ""

    def update_body(self, body: dict[Any, Any]) -> None:
        """Used by Auth to update the request that gets sent to /v1/login-request.

        Args:
            body: existing request dictionary
        """
        body["data"]["AUTHENTICATOR"] = OAUTH_AUTHENTICATOR
        body["data"]["TOKEN"] = self._oauth_token

    def construct_url(self) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self._state,
        }
        if self.scope:
            params["scope"] = self.scope
        if self.pkce:
            self._verifier = secrets.token_urlsafe(43)
            # calculate challenge and verifier
            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(self._verifier.encode("utf-8")).digest()
                )
                .decode("utf-8")
                .rstrip("=")
            )
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
        url_params = urllib.parse.urlencode(params)
        url = f"{self.authentication_url}?{url_params}"
        return url

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
        hostname = "127.0.0.1"
        http_server = AuthHttpServer(hostname=hostname)
        self.redirect_uri = self.redirect_uri.format(port=http_server.port)
        url = self.construct_url()
        logger.debug("authenticating with OAuth code flow")
        logger.debug("step 1: going to open authorization URL")
        print(
            "Initiating login request with your identity provider. A "
            "browser window should have opened for you to complete the "
            "login. If you can't see it, check existing browser windows, "
            "or your OS settings. Press CTRL+C to abort and try again..."
        )
        if webbrowser.open(url):
            data, socket_connection = http_server.receive_block()
            try:
                if not self._process_options(
                    data, socket_connection, hostname, http_server.port
                ):
                    self._send_response(data, socket_connection)
            finally:
                socket_connection.shutdown(socket.SHUT_RDWR)
                socket_connection.close()
            _, url, _ = data[0].split(maxsplit=2)
            token = self._process_get_url(url)
        else:
            print(
                "We were unable to open a browser window for you, "
                "please open the URL above manually then paste the "
                "URL you are redirected to into the terminal."
            )
            url = input("Enter the URL the OAuth flow redirected you to: ")
            token = self._process_get_url(url)
            if not token:
                self._handle_failure(
                    conn=conn,
                    ret={
                        "code": ER_UNABLE_TO_OPEN_BROWSER,
                        "message": (
                            "Unable to open a browser in this environment and "
                            "OAuth URL contained no token"
                        ),
                    },
                )
                return
        logger.debug("step 2: received OAUTH callback")
        q_params = _get_query_params(url)
        code = q_params["code"][0]
        state = q_params["state"][0]
        if state != self._state:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_OAUTH_STATE_CHANGED,
                    "message": "State changed during OAuth process.",
                },
            )
        logger.debug(
            "received oauth code: %s and state: %s", "*" * len(code), "*" * len(state)
        )
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
        }
        if self.client_secret:
            fields["client_secret"] = self.client_secret
        if self.pkce:
            assert self._verifier is not None
            fields["code_verifier"] = self._verifier

        resp = urllib3.PoolManager().request_encode_body(  # TODO: use network pool to gain use of proxy settings and so on
            "POST",
            self.token_request_url,
            headers={
                "Basic": base64.b64encode(
                    f"{self.client_id}:{self.client_secret}".encode()
                )
            },
            encode_multipart=False,
            fields=fields,
        )
        try:
            self._oauth_token = json.loads(resp.data)["access_token"]
        except (
            json.JSONDecodeError,
            KeyError,
        ):
            logger.error("oauth reponse invalid, does not contain 'access_token'")
            logger.debug(
                "received the following response body when requesting oauth token: %s",
                resp.data,
            )
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_IDP_CONNECTION_ERROR,
                    "message": "Invalid HTTP request from web browser. Idp "
                    "authentication could have failed.",
                },
            )
        return

    def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        conn.authenticate_with_retry(self)
        return {"success": True}

    def _check_post_requested(
        self, data: list[str]
    ) -> tuple[str, str] | tuple[None, None]:
        request_line = None
        header_line = None
        origin_line = None
        for line in data:
            if line.startswith("Access-Control-Request-Method:"):
                request_line = line
            elif line.startswith("Access-Control-Request-Headers:"):
                header_line = line
            elif line.startswith("Origin:"):
                origin_line = line

        if (
            not request_line
            or not header_line
            or not origin_line
            or request_line.split(":")[1].strip() != "POST"
        ):
            return (None, None)

        return (
            header_line.split(":")[1].strip(),
            ":".join(origin_line.split(":")[1:]).strip(),
        )

    def _process_options(
        self, data: list[str], socket_client: socket.socket, hostname: str, port: int
    ) -> bool:
        """Allows JS Ajax access to this endpoint."""
        for line in data:
            if line.startswith("OPTIONS "):
                break
        else:
            return False
        requested_headers, requested_origin = self._check_post_requested(data)
        if requested_headers is None or requested_origin is None:
            return False

        if not self._validate_origin(requested_origin, hostname, port):
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
        socket_client.sendall("\r\n".join(content).encode("utf-8"))
        return True

    def _validate_origin(self, requested_origin: str, hostname: str, port: int) -> bool:
        ret = urlsplit(requested_origin)
        netloc = ret.netloc.split(":")
        host_got = netloc[0]
        port_got = (
            netloc[1] if len(netloc) > 1 else (443 if self._protocol == "https" else 80)
        )

        return (
            ret.scheme == self._protocol and host_got == hostname and port_got == port
        )

    def _send_response(self, data: list[str], socket_client: socket.socket) -> None:
        if not self._is_request_get(data):
            return  # error

        response = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html",
        ]
        if self._origin:
            msg = json.dumps({"consent": self.consent_cache_id_token})
            response.append(f"Access-Control-Allow-Origin: {self._origin}")
            response.append("Vary: Accept-Encoding, Origin")
        else:
            msg = f"""
<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<link rel="icon" href="data:,">
<title>OAuth Response for Snowflake</title></head>
<body>
Your identity was confirmed and propagated to Snowflake {self._application}.
You can close this window now and go back where you started from.
</body></html>"""
        response.append(f"Content-Length: {len(msg)}")
        response.append("")
        response.append(msg)

        socket_client.sendall("\r\n".join(response).encode("utf-8"))

    def _process_get_url(self, url: str) -> str | None:
        parsed = parse_qs(urlparse(url).query)
        try:
            token = parsed["token"][0]
            return token
        except (KeyError, IndexError):
            return

    def _is_request_get(self, data: list[str]) -> bool:
        """Whether an HTTP request is a GET."""
        for line in data:
            if line.startswith("GET "):
                return True
        return False
