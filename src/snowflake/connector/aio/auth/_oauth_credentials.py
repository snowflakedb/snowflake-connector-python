#!/usr/bin/env python

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ...auth.oauth_credentials import (
    AuthByOauthCredentials as AuthByOauthCredentialsSync,
)
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByOauthCredentials(AuthByPluginAsync, AuthByOauthCredentialsSync):
    """Async version of OAuth client credentials authenticator."""

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str,
        token_request_url: str,
        scope: str,
        connection: SnowflakeConnection | None = None,
        credentials_in_body: bool = False,
        **kwargs,
    ) -> None:
        """Initializes an instance with OAuth client credentials parameters."""
        logger.debug(
            "OAuth authentication is not supported in async version - falling back to sync implementation"
        )
        AuthByOauthCredentialsSync.__init__(
            self,
            application=application,
            client_id=client_id,
            client_secret=client_secret,
            token_request_url=token_request_url,
            scope=scope,
            connection=connection,
            credentials_in_body=credentials_in_body,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByOauthCredentialsSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByOauthCredentialsSync.prepare(self, **kwargs)

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
        AuthByOauthCredentialsSync.update_body(self, body)

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
