#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import typing

from snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN

from .by_plugin import AuthByPlugin, AuthType


class AuthByPAT(AuthByPlugin):

    def __init__(self, pat_token: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._pat_token: str | None = pat_token

    def type_(self) -> AuthType:
        return AuthType.PAT

    def reset_secrets(self) -> None:
        self._pat_token = None

    def update_body(self, body: dict[typing.Any, typing.Any]) -> None:
        body["data"]["AUTHENTICATOR"] = PROGRAMMATIC_ACCESS_TOKEN
        body["data"]["TOKEN"] = self._pat_token

    def prepare(
        self,
        **kwargs: typing.Any,
    ) -> None:
        """Nothing to do here, token should be obtained outside the driver."""
        pass

    def reauthenticate(self, **kwargs: typing.Any) -> dict[str, bool]:
        return {"success": False}

    @property
    def assertion_content(self) -> str | None:
        """Returns the token."""
        return self._pat_token
