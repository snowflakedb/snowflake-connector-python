#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from ...auth.default import AuthByDefault
from .by_plugin_async import AuthByPluginAsync


class AuthByDefaultAsync(AuthByPluginAsync, AuthByDefault):
    async def reset_secrets(self) -> None:
        self._password = None

    async def prepare(self, **kwargs: Any) -> None:
        AuthByDefault.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByDefault.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the password if available."""
        AuthByDefault.update_body(self, body)
