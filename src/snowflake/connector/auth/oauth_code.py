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

from ..compat import parse_qs, urlparse, urlsplit
from ..constants import OAUTH_TYPE_AUTHORIZATION_CODE
from ..errorcode import (
    ER_INVALID_VALUE,
    ER_OAUTH_CALLBACK_ERROR,
    ER_OAUTH_SERVER_TIMEOUT,
    ER_OAUTH_STATE_CHANGED,
    ER_UNABLE_TO_OPEN_BROWSER,
)
from ..errors import Error, ProgrammingError
from ..token_cache import TokenCache
from ._http_server import AuthHttpServer
from ._oauth_base import AuthByOAuthBase

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)

BUF_SIZE = 16384


def _get_query_params(
    url: str,
) -> dict[str, list[str]]:
    parsed = parse_qs(urlparse(url).query)
    return parsed


class AuthByOauthCode(AuthByOAuthBase):
    """Authenticates user by OAuth code flow."""

    _LOCAL_APPLICATION_CLIENT_CREDENTIALS = "LOCAL_APPLICATION"

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str,
        authentication_url: str,
        token_request_url: str,
        redirect_uri: str,
        scope: str,
        host: str,
        pkce_enabled: bool = True,
        token_cache: TokenCache | None = None,
        refresh_token_enabled: bool = False,
        external_browser_timeout: int | None = None,
        enable_single_use_refresh_tokens: bool = False,
        connection: SnowflakeConnection | None = None,
        **kwargs,
    ) -> None:
        authentication_url, redirect_uri = self._validate_oauth_code_uris(
            authentication_url, redirect_uri, connection
        )
        client_id, client_secret = self._validate_client_credentials_with_defaults(
            client_id,
            client_secret,
            authentication_url,
            token_request_url,
            host,
            connection,
        )

        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            token_request_url=token_request_url,
            scope=scope,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
            **kwargs,
        )
        self._application = application
        self._origin: str | None = None
        self._authentication_url = authentication_url
        self._redirect_uri = redirect_uri
        self._state = secrets.token_urlsafe(43)
        logger.debug("chose oauth state: %s", "".join("*" for _ in self._state))
        self._protocol = "http"
        self._pkce_enabled = pkce_enabled
        if pkce_enabled:
            logger.debug("oauth pkce is going to be used")
        self._verifier: str | None = None
        self._external_browser_timeout = external_browser_timeout
        self._enable_single_use_refresh_tokens = enable_single_use_refresh_tokens

    def _get_oauth_type_id(self) -> str:
        return OAUTH_TYPE_AUTHORIZATION_CODE

    def _request_tokens(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> (str | None, str | None):
        """Web Browser based Authentication."""
        logger.debug("authenticating with OAuth authorization code flow")
        with AuthHttpServer(self._redirect_uri) as callback_server:
            code = self._do_authorization_request(callback_server, conn)
            return self._do_token_request(code, callback_server, conn)

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

    @staticmethod
    def _has_code(url: str) -> bool:
        return "code" in parse_qs(urlparse(url).query)

    @staticmethod
    def _is_request_get(data: list[str]) -> bool:
        """Whether an HTTP request is a GET."""
        return any(line.startswith("GET ") for line in data)

    def _construct_authorization_request(self, redirect_uri: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "state": self._state,
        }
        if self._scope:
            params["scope"] = self._scope
        if self._pkce_enabled:
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
        url = f"{self._authentication_url}?{url_params}"
        return url

    def _do_authorization_request(
        self,
        callback_server: AuthHttpServer,
        connection: SnowflakeConnection,
    ) -> str | None:
        authorization_request = self._construct_authorization_request(
            callback_server.url
        )
        logger.debug("step 1: going to open authorization URL")
        print(
            "Initiating login request with your identity provider. A "
            "browser window should have opened for you to complete the "
            "login. If you can't see it, check existing browser windows, "
            "or your OS settings. Press CTRL+C to abort and try again..."
        )
        # TODO(SNOW-2229411) Investigate if Session manager / Http Config should be used here.
        code, state = (
            self._receive_authorization_callback(callback_server, connection)
            if webbrowser.open(authorization_request)
            else self._ask_authorization_callback_from_user(
                authorization_request, connection
            )
        )
        if not code:
            self._handle_failure(
                conn=connection,
                ret={
                    "code": ER_UNABLE_TO_OPEN_BROWSER,
                    "message": (
                        "Unable to open a browser in this environment and "
                        "OAuth URL contained no authorization code."
                    ),
                },
            )
            return None
        if state != self._state:
            self._handle_failure(
                conn=connection,
                ret={
                    "code": ER_OAUTH_STATE_CHANGED,
                    "message": "State changed during OAuth process.",
                },
            )
            logger.debug(
                "received oauth code: %s and state: %s",
                "*" * len(code),
                "*" * len(state),
            )
            return None
        return code

    def _do_token_request(
        self,
        code: str,
        callback_server: AuthHttpServer,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("step 2: received OAuth callback, requesting token")
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_server.url,
        }
        if self._enable_single_use_refresh_tokens:
            fields["enable_single_use_refresh_tokens"] = "true"
        if self._pkce_enabled:
            assert self._verifier is not None
            fields["code_verifier"] = self._verifier
        return self._get_request_token_response(connection, fields)

    def _receive_authorization_callback(
        self,
        http_server: AuthHttpServer,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("trying to receive authorization redirected uri")
        data, socket_connection = http_server.receive_block(
            timeout=self._external_browser_timeout
        )
        if socket_connection is None:
            self._handle_failure(
                conn=connection,
                ret={
                    "code": ER_OAUTH_SERVER_TIMEOUT,
                    "message": "Unable to receive the OAuth message within a given timeout. Please check the redirect URI and try again.",
                },
            )
            return None, None
        try:
            if not self._process_options(
                data, socket_connection, http_server.hostname, http_server.port
            ):
                self._send_response(data, socket_connection)
            socket_connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            socket_connection.close()
        return self._parse_authorization_redirected_request(
            data[0].split(maxsplit=2)[1],
            connection,
        )

    def _ask_authorization_callback_from_user(
        self,
        authorization_request: str,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("requesting authorization redirected url from user")
        print(
            "We were unable to open a browser window for you, "
            "please open the URL manually then paste the "
            "URL you are redirected to into the terminal:\n"
            f"{authorization_request}"
        )
        received_redirected_request = input(
            "Enter the URL the OAuth flow redirected you to: "
        )
        code, state = self._parse_authorization_redirected_request(
            received_redirected_request,
            connection,
        )
        if not code:
            self._handle_failure(
                conn=connection,
                ret={
                    "code": ER_UNABLE_TO_OPEN_BROWSER,
                    "message": (
                        "Unable to open a browser in this environment and "
                        "OAuth URL contained no code"
                    ),
                },
            )
        return code, state

    def _parse_authorization_redirected_request(
        self,
        url: str,
        conn: SnowflakeConnection,
    ) -> (str | None, str | None):
        parsed = parse_qs(urlparse(url).query)
        if "error" in parsed:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_OAUTH_CALLBACK_ERROR,
                    "message": f"Oauth callback returned an {parsed['error'][0]} error{': ' + parsed['error_description'][0] if 'error_description' in parsed else '.'}",
                },
            )
        return parsed.get("code", [None])[0], parsed.get("state", [None])[0]

    @staticmethod
    def _is_snowflake_as_idp(
        authentication_url: str, token_request_url: str, host: str
    ) -> bool:
        return (authentication_url == "" or host in authentication_url) and (
            token_request_url == "" or host in token_request_url
        )

    def _eligible_for_default_client_credentials(
        self,
        client_id: str,
        client_secret: str,
        authorization_url: str,
        token_request_url: str,
        host: str,
    ) -> bool:
        return (
            (client_id == "" or client_secret is None)
            and (client_secret == "" or client_secret is None)
            and self.__class__._is_snowflake_as_idp(
                authorization_url, token_request_url, host
            )
        )

    def _validate_client_credentials_with_defaults(
        self,
        client_id: str,
        client_secret: str,
        authorization_url: str,
        token_request_url: str,
        host: str,
        connection: SnowflakeConnection,
    ) -> tuple[str, str] | None:
        if self._eligible_for_default_client_credentials(
            client_id, client_secret, authorization_url, token_request_url, host
        ):
            return (
                self.__class__._LOCAL_APPLICATION_CLIENT_CREDENTIALS,
                self.__class__._LOCAL_APPLICATION_CLIENT_CREDENTIALS,
            )
        else:
            self._validate_client_credentials_present(
                client_id, client_secret, connection
            )
            return client_id, client_secret

    @staticmethod
    def _validate_oauth_code_uris(
        authorization_url: str, redirect_uri: str, connection: SnowflakeConnection
    ) -> tuple[str, str]:
        if authorization_url and not authorization_url.startswith("https://"):
            Error.errorhandler_wrapper(
                connection,
                None,
                ProgrammingError,
                {
                    "msg": "OAuth supports only authorization urls that use 'https' scheme",
                    "errno": ER_INVALID_VALUE,
                },
            )
        if redirect_uri and not (
            redirect_uri.startswith("http://") or redirect_uri.startswith("https://")
        ):
            Error.errorhandler_wrapper(
                connection,
                None,
                ProgrammingError,
                {
                    "msg": "OAuth supports only authorization urls that use 'http(s)' scheme",
                    "errno": ER_INVALID_VALUE,
                },
            )
        return authorization_url, redirect_uri
