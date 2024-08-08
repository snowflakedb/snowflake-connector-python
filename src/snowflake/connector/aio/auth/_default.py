#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from ...auth.default import AuthByDefault as AuthByDefaultSync
from ._by_plugin import AuthByPlugin


class AuthByDefault(AuthByPlugin, AuthByDefaultSync):
    async def reset_secrets(self) -> None:
        self._password = None

    async def prepare(self, **kwargs: Any) -> None:
        AuthByDefaultSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByDefaultSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the password if available."""
        AuthByDefaultSync.update_body(self, body)
