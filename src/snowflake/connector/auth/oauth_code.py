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
from urllib.error import HTTPError, URLError

import urllib3

from ..compat import parse_qs, urlparse, urlsplit
from ..constants import OAUTH_TYPE_AUTHORIZATION_CODE
from ..errorcode import (
    ER_FAILED_TO_REQUEST,
    ER_IDP_CONNECTION_ERROR,
    ER_OAUTH_CALLBACK_ERROR,
    ER_OAUTH_SERVER_TIMEOUT,
    ER_OAUTH_STATE_CHANGED,
    ER_UNABLE_TO_OPEN_BROWSER,
)
from ..errors import InterfaceError
from ..network import OAUTH_AUTHENTICATOR
from ._auth import Auth
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

    _ACCESS_TOKEN_CACHE_KEY = "OAUTH_ACCESS_TOKEN"
    _REFRESH_TOKEN_CACHE_KEY = "OAUTH_REFRESH_TOKEN"

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str | None,
        authentication_url: str,
        token_request_url: str,
        redirect_uri: str,
        scope: str,
        pkce_enabled: bool = False,
        token_cache_enabled: bool = False,
        refresh_token_enabled: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        if "{port}" not in redirect_uri:
            raise InterfaceError("redirect_uri needs '{port}' placeholder for now")
        self._application = application
        self._origin: str | None = None
        self._client_id = client_id
        self._client_secret = client_secret
        self._authentication_url = authentication_url
        self._token_request_url = token_request_url
        self._redirect_uri = redirect_uri
        self._scope = scope
        self._state = secrets.token_urlsafe(43)
        logger.debug("chose oauth state: %s", "".join("*" for _ in self._state))
        self._access_token = None
        self._refresh_token = None
        self._protocol = "http"
        self._pkce_enabled = pkce_enabled
        if pkce_enabled:
            logger.debug("oauth pkce is going to be used")
        self._token_cache_enabled = token_cache_enabled
        if token_cache_enabled:
            logger.debug("token cache is going to be used if needed")
        self._refresh_token_enabled = refresh_token_enabled
        if refresh_token_enabled:
            logger.debug("oauth refresh token is going to be used if needed")
        self._verifier: str | None = None

    def reset_secrets(self) -> None:
        logger.debug("resetting secrets")
        self._access_token = None
        self._refresh_token = None

    @property
    def type_(self) -> AuthType:
        return AuthType.OAUTH

    @property
    def assertion_content(self) -> str:
        """Returns the token."""
        return self._access_token or ""

    def update_body(self, body: dict[Any, Any]) -> None:
        """Used by Auth to update the request that gets sent to /v1/login-request.

        Args:
            body: existing request dictionary
        """
        body["data"]["AUTHENTICATOR"] = OAUTH_AUTHENTICATOR
        body["data"]["TOKEN"] = self._access_token
        body["data"]["OAUTH_TYPE"] = OAUTH_TYPE_AUTHORIZATION_CODE

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
        logger.debug("authenticating with OAuth authorization code flow")
        self._pop_cached_tokens(account, user)
        if self._access_token:
            logger.info(
                "OAuth access token is already available in cache, no need to update it."
            )
            return
        with AuthHttpServer() as callback_server:
            code = self._do_authorization_request(callback_server, conn)
            access_token, refresh_token = self._do_token_request(
                code, callback_server, conn
            )
        self._reset_access_token(access_token)
        self._reset_refresh_token(refresh_token)

    def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        self._reset_access_token()
        if self._refresh_token:
            logger.debug(
                "OAuth refresh token is available, try to use it and get a new access token"
            )
            self._do_refresh_token(conn=conn)
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

    @staticmethod
    def _has_code(url: str) -> bool:
        return "code" in parse_qs(urlparse(url).query)

    @staticmethod
    def _is_request_get(data: list[str]) -> bool:
        """Whether an HTTP request is a GET."""
        return any(line.startswith("GET ") for line in data)

    def _construct_authorization_request(self, redirect_port: int) -> str:
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri.format(port=redirect_port),
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
            callback_server.port
        )
        logger.debug("step 1: going to open authorization URL")
        print(
            "Initiating login request with your identity provider. A "
            "browser window should have opened for you to complete the "
            "login. If you can't see it, check existing browser windows, "
            "or your OS settings. Press CTRL+C to abort and try again..."
        )
        code, state = (
            self._receive_authorization_callback(callback_server, connection)
            if webbrowser.open(authorization_request)
            else self._ask_authorization_callback_from_user(connection)
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

    def _create_token_request_headers(self) -> dict[str, str]:
        return {
            "Authorization": "Basic "
            + base64.b64encode(
                f"{self._client_id}:{self._client_secret}".encode()
            ).decode(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

    def _do_token_request(
        self,
        code: str,
        callback_server: AuthHttpServer,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("step 2: received OAUTH callback, requesting token")
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri.format(port=callback_server.port),
        }
        if self._pkce_enabled:
            assert self._verifier is not None
            fields["code_verifier"] = self._verifier
        resp = urllib3.PoolManager().request_encode_body(
            # TODO: use network pool to gain use of proxy settings and so on
            "POST",
            self._token_request_url,
            headers=self._create_token_request_headers(),
            encode_multipart=False,
            fields=fields,
        )
        try:
            logger.debug("OAuth IdP response received, try to parse it")
            json_resp: dict = json.loads(resp.data)
            access_token = json_resp["access_token"]
            refresh_token = json_resp.get("refresh_token")
            return access_token, refresh_token
        except (
            json.JSONDecodeError,
            KeyError,
        ):
            logger.error("oauth response invalid, does not contain 'access_token'")
            logger.debug(
                "received the following response body when requesting oauth token: %s",
                resp.data,
            )
            self._handle_failure(
                conn=connection,
                ret={
                    "code": ER_IDP_CONNECTION_ERROR,
                    "message": "Invalid HTTP request from web browser. Idp "
                    "authentication could have failed.",
                },
            )
        return None, None

    def _receive_authorization_callback(
        self,
        http_server: AuthHttpServer,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("trying to receive authorization redirected uri")
        data, socket_connection = http_server.receive_block()
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
        finally:
            socket_connection.shutdown(socket.SHUT_RDWR)
            socket_connection.close()
        return self._parse_authorization_redirected_request(
            data[0].split(maxsplit=2)[1],
            connection,
        )

    def _ask_authorization_callback_from_user(
        self,
        connection: SnowflakeConnection,
    ) -> (str | None, str | None):
        logger.debug("requesting authorization redirected url from user")
        print(
            "We were unable to open a browser window for you, "
            "please open the URL above manually then paste the "
            "URL you are redirected to into the terminal."
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

    def _reset_access_token(self, access_token: str | None = None) -> None:
        """Updates OAuth access token both in memory and in the token cache if enabled"""
        logger.debug(
            "resetting access token to %s",
            "*" * len(access_token) if access_token else None,
        )
        self._access_token = access_token
        if not self._token_cache_enabled:
            return
        if access_token:
            Auth.write_temporary_credential(
                *self._token_cache_prefix, self._ACCESS_TOKEN_CACHE_KEY, access_token
            )
        else:
            Auth.delete_temporary_credential(
                *self._token_cache_prefix, self._ACCESS_TOKEN_CACHE_KEY
            )

    def _reset_refresh_token(self, refresh_token: str | None = None) -> None:
        """Updates OAuth refresh token both in memory and in the token cache if necessary"""
        logger.debug(
            "resetting access token to %s",
            "*" * len(refresh_token) if refresh_token else None,
        )
        if not self._refresh_token_enabled:
            return
        self._refresh_token = refresh_token
        if not self._token_cache_enabled:
            return
        if refresh_token:
            Auth.write_temporary_credential(
                *self._token_cache_prefix, self._REFRESH_TOKEN_CACHE_KEY, refresh_token
            )
        else:
            Auth.delete_temporary_credential(
                *self._token_cache_prefix, self._REFRESH_TOKEN_CACHE_KEY
            )

    def _pop_cached_tokens(self, account: str, user: str) -> None:
        """Retrieves OAuth access and refresh tokens from the token cache if enabled"""
        if self._token_cache_enabled:
            self._token_cache_prefix = (account, user)
            self._access_token = Auth.read_temporary_credential(
                *self._token_cache_prefix, self._ACCESS_TOKEN_CACHE_KEY
            )
            self._refresh_token = (
                Auth.read_temporary_credential(
                    *self._token_cache_prefix, self._REFRESH_TOKEN_CACHE_KEY
                )
                if self._refresh_token_enabled
                else None
            )

    def _get_refresh_token_response(
        self, conn: SnowflakeConnection
    ) -> urllib3.BaseHTTPResponse | None:
        fields = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }
        if self._scope:
            fields["scope"] = self._scope
        try:
            return urllib3.PoolManager().request_encode_body(
                # TODO: use network pool to gain use of proxy settings and so on
                "POST",
                self._token_request_url,
                encode_multipart=False,
                headers=self._create_token_request_headers(),
                fields=fields,
            )
        except HTTPError as e:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_FAILED_TO_REQUEST,
                    "message": f"Failed to request new OAuth access token with a refresh token,"
                    f" url={e.url}, code={e.code}, reason={e.reason}",
                },
            )
        except URLError as e:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_FAILED_TO_REQUEST,
                    "message": f"Failed to request new OAuth access token with a refresh token, reason: {e.reason}",
                },
            )
        except Exception:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_FAILED_TO_REQUEST,
                    "message": "Failed to request new OAuth access token with a refresh token by unknown reason",
                },
            )
        return None

    def _do_refresh_token(self, conn: SnowflakeConnection) -> None:
        """If a refresh token is available exchanges it with a new access token.
        Updates self as a side-effect. Needs at lest self._refresh_token and client_id set.
        """
        if not self._refresh_token_enabled:
            logger.debug("refresh_token feature is disabled")
            return

        resp = self._get_refresh_token_response(conn)
        if not resp:
            logger.info(
                "Failed to exchange the refresh token on a new OAuth access token"
            )
            self._reset_refresh_token()
            return

        try:
            json_resp = json.loads(resp.data.decode())
            self._reset_access_token(json_resp["access_token"])
            self._reset_refresh_token(json_resp.get("refresh_token"))
        except (
            json.JSONDecodeError,
            KeyError,
        ):
            logger.error(
                "refresh token exchange response did not contain 'access_token'"
            )
            logger.debug(
                "received the following response body when exchanging refresh token: %s",
                resp.data,
            )
            self._reset_refresh_token()
