#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

#
# Copyright (c) 2012-2024 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from .by_plugin import AuthByPlugin, AuthType


class AuthByStoredProcConnection(AuthByPlugin):
    """Stored Procedure Authentication.

    It is a dummy auth that requires no extra connection establishment.
    """

    def __init__(self):
        super().__init__()

    @property
    def type_(self) -> AuthType:
        return AuthType.STORED_PROC

    @property
    def assertion_content(self) -> str:
        """Returns the token."""
        pass

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
