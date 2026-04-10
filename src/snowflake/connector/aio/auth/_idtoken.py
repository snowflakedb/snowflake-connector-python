from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...auth.idtoken import AuthByIdToken as AuthByIdTokenSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync
from ._webbrowser import AuthByWebBrowser

if TYPE_CHECKING:
    from .._connection import SnowflakeConnection


class AuthByIdToken(AuthByPluginAsync, AuthByIdTokenSync):
    def __init__(
        self,
        id_token: str,
        application: str,
        protocol: str | None,
        host: str | None,
        port: str | None,
        **kwargs,
    ) -> None:
        """Initialized an instance with an IdToken."""
        AuthByIdTokenSync.__init__(
            self, id_token, application, protocol, host, port, **kwargs
        )

    async def reset_secrets(self) -> None:
        AuthByIdTokenSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByIdTokenSync.prepare(self, **kwargs)

    async def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, bool]:
        conn.auth_class = AuthByWebBrowser(
            application=self._application,
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            timeout=conn.login_timeout,
            backoff_generator=conn._backoff_generator,
        )
        await conn._authenticate(conn.auth_class)
        await conn._auth_class.reset_secrets()
        return {"success": True}

    async def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the id_token if available."""
        AuthByIdTokenSync.update_body(self, body)
