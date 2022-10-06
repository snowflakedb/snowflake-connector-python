#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

from snowflake.connector.reauth_by_plugin import ReauthByPlugin


# By default, we don't allow reauth so this class just returns False
class ReauthByDefault(ReauthByPlugin):
    def reauthenticate(self) -> dict[str, bool]:
        return {"success": False}
