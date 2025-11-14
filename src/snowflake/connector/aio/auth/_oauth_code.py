#!/usr/bin/env python

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ...auth.oauth_code import AuthByOauthCode as AuthByOauthCodeSync
from ...token_cache import TokenCache
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


# this code mostly falls back to sync implementation
# TODO: SNOW-2324426
class AuthByOauthCode(AuthByPluginAsync, AuthByOauthCodeSync):
    """Async version of OAuth authorization code authenticator."""

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
        uri: str | None = None,
        **kwargs,
    ) -> None:
        """Initializes an instance with OAuth authorization code parameters."""
        logger.debug(
            "OAuth authentication is not supported in async version - falling back to sync implementation"
        )
        AuthByOauthCodeSync.__init__(
            self,
            application=application,
            client_id=client_id,
            client_secret=client_secret,
            authentication_url=authentication_url,
            token_request_url=token_request_url,
            redirect_uri=redirect_uri,
            scope=scope,
            host=host,
            pkce_enabled=pkce_enabled,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
            external_browser_timeout=external_browser_timeout,
            enable_single_use_refresh_tokens=enable_single_use_refresh_tokens,
            connection=connection,
            uri=uri,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByOauthCodeSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByOauthCodeSync.prepare(self, **kwargs)

    async def reauthenticate(
        self, conn: SnowflakeConnection, **kwargs: Any
    ) -> dict[str, bool]:
        """Override to use async connection properly."""
        # Call the sync reset logic but handle the connection retry ourselves
        self._reset_access_token()
        if self._pop_cached_refresh_token():
            logger.debug(
                "OAuth refresh token is available, try to use it and get a new access token"
            )
            # this part is a little hacky - will need to refactor that in future.
            # we treat conn as a sync connection here, but this method only reads data from the object - which should be fine.
            self._do_refresh_token(conn=conn)
        # Use async authenticate_with_retry
        await conn.authenticate_with_retry(self)
        return {"success": True}

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByOauthCodeSync.update_body(self, body)

    def _handle_failure(
        self,
        *,
        conn: SnowflakeConnection,
        ret: dict[Any, Any],
        **kwargs: Any,
    ) -> None:
        """Override to ensure proper error handling in async context."""
        # Use sync error handling directly to avoid async/sync mismatch
        from ...errors import DatabaseError, Error
        from ...sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED

        Error.errorhandler_wrapper(
            conn,
            None,
            DatabaseError,
            {
                "msg": "Failed to connect to DB: {host}:{port}, {message}".format(
                    host=conn._rest._host,
                    port=conn._rest._port,
                    message=ret["message"],
                ),
                "errno": int(ret.get("code", -1)),
                "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            },
        )
