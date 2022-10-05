#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from typing import Dict

from snowflake.connector.reauth_by_plugin import ReauthByPlugin


# By default, we don't allow reauth so this class just returns False
class ReauthByDefault(ReauthByPlugin):

    def reauthenticate(self) -> Dict[str, bool]:
        return {"success": False}
