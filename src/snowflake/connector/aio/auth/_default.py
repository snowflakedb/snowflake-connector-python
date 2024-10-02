#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from logging import getLogger
from typing import Any

from ...auth.default import AuthByDefault as AuthByDefaultSync
from ._by_plugin import AuthByPlugin

logger = getLogger(__name__)


class AuthByDefault(AuthByPlugin, AuthByDefaultSync):
    def __init__(self, password: str, **kwargs) -> None:
        """Initializes an instance with a password."""
        AuthByDefaultSync.__init__(self, password, **kwargs)

    async def reset_secrets(self) -> None:
        self._password = None

    async def prepare(self, **kwargs: Any) -> None:
        AuthByDefaultSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByDefaultSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the password if available."""
        AuthByDefaultSync.update_body(self, body)

    async def handle_timeout(
        self,
        *,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
        **kwargs: Any,
    ) -> None:
        logger.debug("Invoking base timeout handler")
        await AuthByPlugin.handle_timeout(
            self,
            authenticator=authenticator,
            service_name=service_name,
            account=account,
            user=user,
            password=password,
            delete_params=False,
        )

        logger.debug("Base timeout handler passed, preparing new token before retrying")
        await self.prepare(account=account, user=user)
