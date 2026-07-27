#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError

from ..errorcode import (
    ER_FAILED_TO_REQUEST,
    ER_IDP_CONNECTION_ERROR,
    ER_NO_CLIENT_ID,
    ER_NO_CLIENT_SECRET,
)
from ..errors import Error, ProgrammingError
from ..network import OAUTH_AUTHENTICATOR
from ..proxy import get_proxy_url
from ..secret_detector import SecretDetector
from ..token_cache import TokenCache, TokenKey, TokenType
from ..vendored import urllib3
from ..vendored.requests.utils import get_environ_proxies, select_proxy
from ..vendored.urllib3.poolmanager import ProxyManager
from .by_plugin import AuthByPlugin, AuthType

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class _OAuthTokensMixin:
    """Manages OAuth token caching to avoid repeated browser authentication flows.

    Access tokens: Short-lived (typically 10 minutes), cached to avoid immediate re-auth.
    Refresh tokens: Long-lived (hours/days), used to obtain new access tokens silently.

    Tokens are cached per (user, IDP host) to support multiple OAuth providers/accounts.
    """

    def __init__(
        self,
        token_cache: TokenCache | None,
        refresh_token_enabled: bool,
        idp_host: str,
    ) -> None:
        self._access_token = None
        self._refresh_token_enabled = refresh_token_enabled
        if self._refresh_token_enabled:
            self._refresh_token = None
        self._token_cache = token_cache
        self._idp_host = idp_host
        self._tokens_loaded_from_cache = False  # Prevents re-loading tokens from cache
        if self._token_cache:
            logger.debug("token cache is going to be used if needed")
            self._user: str | None = None
            self._access_token_key: TokenKey | None = None
            if self._refresh_token_enabled:
                self._refresh_token_key: TokenKey | None = None

    def _update_cache_keys(self, user: str) -> None:
        if self._token_cache:
            self._user = user

    def _load_tokens_from_cache(self, user: str) -> bool:
        """Load both access and refresh tokens from cache into memory.

        Called exactly once at connection start. Returns True if access token loaded.
        """
        if self._tokens_loaded_from_cache:
            return self._access_token is not None

        self._tokens_loaded_from_cache = True
        self._update_cache_keys(user)

        # Load access token
        if self._token_cache:
            self._access_token = self._token_cache.retrieve(
                self._get_access_token_cache_key()
            )

        # Load refresh token if enabled
        if self._refresh_token_enabled and self._token_cache:
            self._refresh_token = self._token_cache.retrieve(
                self._get_refresh_token_cache_key()
            )

        return self._access_token is not None

    def _get_access_token_cache_key(self) -> TokenKey | None:
        return (
            TokenKey(self._user, self._idp_host, TokenType.OAUTH_ACCESS_TOKEN)
            if self._token_cache and self._user
            else None
        )

    def _get_refresh_token_cache_key(self) -> TokenKey | None:
        return (
            TokenKey(self._user, self._idp_host, TokenType.OAUTH_REFRESH_TOKEN)
            if self._refresh_token_enabled and self._token_cache and self._user
            else None
        )

    def _invalidate_refresh_token(self) -> None:
        """Clear a confirmed-invalid refresh token from memory and cache.

        A lone remove() does not destroy macOS Keychain ACL entries; only the
        remove-then-store pattern does. Safe to call on definitive IdP rejection.
        """
        self._refresh_token = None
        if self._token_cache:
            key = self._get_refresh_token_cache_key()
            if key:
                self._token_cache.remove(key)

    def _store_tokens(
        self, access_token: str | None = None, refresh_token: str | None = None
    ) -> None:
        """Update tokens in memory and persistent cache.

        Only calls store(), never remove(), to preserve macOS Keychain ACL.
        """
        if access_token is not None:
            logger.debug("storing access token to memory and cache")
            self._access_token = access_token
            if self._token_cache:
                key = self._get_access_token_cache_key()
                if key:
                    self._token_cache.store(key, access_token)

        if self._refresh_token_enabled and refresh_token is not None:
            logger.debug("storing refresh token to memory and cache")
            self._refresh_token = refresh_token
            if self._token_cache:
                key = self._get_refresh_token_cache_key()
                if key:
                    self._token_cache.store(key, refresh_token)

    def _reset_temporary_state(self) -> None:
        self._access_token = None
        self._tokens_loaded_from_cache = False
        if self._refresh_token_enabled:
            self._refresh_token = None
        if self._token_cache:
            self._user = None


class AuthByOAuthBase(AuthByPlugin, _OAuthTokensMixin, ABC):
    """A base abstract class for OAuth authenticators"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_request_url: str,
        scope: str,
        token_cache: TokenCache | None,
        refresh_token_enabled: bool,
        is_snowflake_as_idp: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        _OAuthTokensMixin.__init__(
            self,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
            idp_host=urllib.parse.urlparse(token_request_url).hostname,
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_request_url = token_request_url
        self._scope = scope
        if refresh_token_enabled:
            logger.debug("oauth refresh token is going to be used if needed")
            if self._should_append_offline_access_scope():
                self._scope += (" " if self._scope else "") + "offline_access"
            else:
                logger.debug(
                    "skipping 'offline_access' scope: Snowflake custom OAuth "
                    "uses 'refresh_token' or it is already present in scope"
                )

    def _should_append_offline_access_scope(self) -> bool:
        """Whether to append the OIDC ``offline_access`` scope.

        Snowflake custom OAuth (security integrations of type CUSTOM) does not
        accept ``offline_access`` and instead documents ``refresh_token`` as the
        scope used to request offline access. Appending ``offline_access``
        unconditionally causes ``invalid_scope`` errors against Snowflake's
        authorization server.

        Skip the append when:
          * the token endpoint host is a Snowflake host, OR
          * the user already requested ``refresh_token`` in scope (explicit intent).
        """
        host = (self._idp_host or "").lower()
        if host.endswith(".snowflakecomputing.com") or host.endswith(
            ".snowflakecomputing.cn"
        ):
            return False
        if "refresh_token" in (self._scope or "").split():
            return False
        return True

    @abstractmethod
    def _request_tokens(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
        **kwargs: Any,
    ) -> (str | None, str | None):
        """Request new access and optionally refresh tokens from IdP.

        This function should implement specific tokens querying flow.
        """
        raise NotImplementedError

    @abstractmethod
    def _get_oauth_type_id(self) -> str:
        """Get OAuth specific authenticator id to be passed to Snowflake.

        This function should return a unique OAuth authenticator id.
        """
        raise NotImplementedError

    def reset_secrets(self) -> None:
        logger.debug("resetting secrets")
        self._reset_temporary_state()

    @property
    def type_(self) -> AuthType:
        return AuthType.OAUTH

    @property
    def assertion_content(self) -> str:
        """Returns the token."""
        return self._access_token or ""

    @staticmethod
    def _validate_client_credentials_present(
        client_id: str, client_secret: str, connection: SnowflakeConnection
    ) -> tuple[str, str]:
        if client_id is None or client_id == "":
            Error.errorhandler_wrapper(
                connection,
                None,
                ProgrammingError,
                {
                    "msg": "Oauth code flow requirement 'client_id' is empty",
                    "errno": ER_NO_CLIENT_ID,
                },
            )
        if client_secret is None or client_secret == "":
            Error.errorhandler_wrapper(
                connection,
                None,
                ProgrammingError,
                {
                    "msg": "Oauth code flow requirement 'client_secret' is empty",
                    "errno": ER_NO_CLIENT_SECRET,
                },
            )

        return client_id, client_secret

    def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        """Handle expired access token by trying refresh token or re-authenticating.

        CRITICAL: Calls _request_tokens() directly, NOT prepare(), to avoid loop.
        """
        # Clear expired access token from memory
        self._access_token = None

        # Try refresh using in-memory token (no keychain read)
        if self._refresh_token_enabled and self._refresh_token:
            logger.debug("Attempting to exchange refresh token for new access token")
            self._do_refresh_token(conn=conn)

            if self._access_token is not None:
                logger.debug("Successfully refreshed access token")
                return {"success": True}

            logger.debug("Refresh token exchange failed, falling back to browser auth")

        # No refresh or refresh failed - get fresh tokens via browser
        # Call _request_tokens() DIRECTLY to avoid looping back to prepare()
        access_token, refresh_token = self._request_tokens(
            conn=conn,
            authenticator=conn._authenticator,
            service_name=conn.service_name,
            account=conn.account,
            user=conn.user,
            password=None,
        )
        if access_token is None:
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_FAILED_TO_REQUEST,
                    "message": "Failed to obtain a new OAuth access token during reauthentication",
                },
            )
            return {"success": False}
        self._store_tokens(access_token, refresh_token)

        return {"success": True}

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

        # Load tokens from cache ONCE at the start
        if self._load_tokens_from_cache(user):
            logger.info("OAuth access token is already available in cache")
            return

        # No cached token - request fresh tokens via browser
        access_token, refresh_token = self._request_tokens(
            conn=conn,
            authenticator=authenticator,
            service_name=service_name,
            account=account,
            user=user,
            **kwargs,
        )
        self._store_tokens(access_token, refresh_token)

    def update_body(self, body: dict[Any, Any]) -> None:
        """Used by Auth to update the request that gets sent to /v1/login-request.

        Args:
            body: existing request dictionary
        """
        body["data"]["AUTHENTICATOR"] = OAUTH_AUTHENTICATOR
        body["data"]["TOKEN"] = self._access_token
        if "CLIENT_ENVIRONMENT" not in body["data"]:
            body["data"]["CLIENT_ENVIRONMENT"] = {}
        body["data"]["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] = self._get_oauth_type_id()

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
                "failed to exchange the refresh token on a new OAuth access token"
            )
            # Clear in-memory refresh token - leave keychain alone
            self._refresh_token = None
            return

        try:
            json_resp = json.loads(resp.data.decode())
            access_token = json_resp["access_token"]
            refresh_token = json_resp.get("refresh_token")

            # Store both tokens
            self._store_tokens(access_token, refresh_token)

        except (
            json.JSONDecodeError,
            KeyError,
        ):
            logger.error(
                "refresh token exchange response did not contain 'access_token'"
            )
            logger.debug(
                "received the following response body when exchanging refresh token: %s",
                SecretDetector.mask_secrets(str(resp.data)),
            )
            # IdP responded but rejected the token - evict it from cache so the
            # next connection doesn't waste a round-trip retrying a dead token.
            # A lone remove() is safe and does not destroy macOS Keychain ACL.
            self._invalidate_refresh_token()

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
            # TODO(SNOW-2229411) Session manager should be used here. It may require additional security validation (since we would transition from PoolManager to requests.Session) and some parameters would be passed implicitly. OAuth token exchange must NOT reuse pooled HTTP sessions. We should create a fresh SessionManager with use_pooling=False for each call.
            proxy_url = self._resolve_proxy_url(conn, self._token_request_url)
            http_client = (
                ProxyManager(proxy_url=proxy_url)
                if proxy_url
                else urllib3.PoolManager()
            )
            return http_client.request_encode_body(
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

    def _get_request_token_response(
        self,
        connection: SnowflakeConnection,
        fields: dict[str, str],
    ) -> (str | None, str | None):
        # TODO(SNOW-2229411) Session manager should be used here. It may require additional security validation (since we would transition from PoolManager to requests.Session) and some parameters would be passed implicitly. Token request must bypass HTTP connection pools.
        proxy_url = self._resolve_proxy_url(connection, self._token_request_url)
        http_client = (
            ProxyManager(proxy_url=proxy_url) if proxy_url else urllib3.PoolManager()
        )
        resp = http_client.request_encode_body(
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
                SecretDetector.mask_secrets(str(resp.data)),
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

    def _create_token_request_headers(self) -> dict[str, str]:
        return {
            "Authorization": "Basic "
            + base64.b64encode(
                f"{self._client_id}:{self._client_secret}".encode()
            ).decode(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

    @staticmethod
    def _log_if_http_in_use(url: str) -> None:
        """Log a warning if the URL uses insecure HTTP protocol.

        Args:
            url: The URL to check for HTTP usage
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.scheme == "http":
                logger.warning(
                    "OAuth URL uses insecure HTTP protocol: %s",
                    SecretDetector.mask_secrets(url),
                )
        except Exception as e:
            logger.warning(
                "Cannot parse URL: %s. %s",
                SecretDetector.mask_secrets(url),
                e,
            )

    @staticmethod
    def _resolve_proxy_url(
        connection: SnowflakeConnection, request_url: str
    ) -> str | None:
        # TODO(SNOW-2229411) Session manager should be used instead. It may require additional security validation.
        """Resolve proxy URL from explicit config first, then environment variables."""
        # First try explicit proxy configuration from connection parameters
        proxy_url = get_proxy_url(
            connection.proxy_host,
            connection.proxy_port,
            connection.proxy_user,
            connection.proxy_password,
        )

        if proxy_url:
            return proxy_url

        # Fall back to environment variables (HTTP_PROXY, HTTPS_PROXY)
        # Use proper proxy selection that considers the URL scheme
        proxies = get_environ_proxies(request_url)
        return select_proxy(request_url, proxies)
