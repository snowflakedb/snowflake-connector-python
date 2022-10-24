#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from .by_plugin import AuthByPlugin, AuthType


class AuthByDefault(AuthByPlugin):
    """Default username and password authenticator."""

    @property
    def type_(self) -> AuthType:
        return AuthType.DEFAULT

    @property
    def assertion_content(self) -> str:
        return "*********"

    def __init__(self, password) -> None:
        """Initializes an instance with a password."""
        super().__init__()
        self._password = password

    def authenticate(
        self,
        authenticator: str,
        service_name: str,
        account: str,
        user: str,
        password: str,
    ) -> None:
        pass

    def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the password if available."""
        if self._password:
            body["data"]["PASSWORD"] = self._password
