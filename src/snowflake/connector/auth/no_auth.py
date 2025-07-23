#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from .by_plugin import AuthByPlugin, AuthType


class AuthNoAuth(AuthByPlugin):
    """No-auth Authentication.

    It is a dummy auth that requires no extra connection establishment.
    """

    @property
    def type_(self) -> AuthType:
        return AuthType.NO_AUTH

    @property
    def assertion_content(self) -> str | None:
        return None

    def __init__(self) -> None:
        super().__init__()

    def reset_secrets(self) -> None:
        pass

    def prepare(
        self,
        **kwargs: Any,
    ) -> None:
        pass

    def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return {"success": True}

    def update_body(self, body: dict[Any, Any]) -> None:
        pass
