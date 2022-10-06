#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

from snowflake.connector.auth_webbrowser import AuthByWebBrowser
from snowflake.connector.reauth_by_plugin import ReauthByPlugin


class ReauthByWebBrowser(ReauthByPlugin):
    def reauthenticate(self) -> dict[str, bool]:
        auth_instance = AuthByWebBrowser(
            self.conn.rest,
            self.conn.application,
            protocol=self.conn._protocol,
            host=self.conn.host,
            port=self.conn.port,
        )
        self.conn._authenticate(auth_instance)
        return {"success": True}
