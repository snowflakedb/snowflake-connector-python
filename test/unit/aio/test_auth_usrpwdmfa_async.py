#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from snowflake.connector.aio.auth._usrpwdmfa import AuthByUsrPwdMfa


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByUsrPwdMfa.mro().index(AuthByPluginAsync) < AuthByUsrPwdMfa.mro().index(
        AuthByPluginSync
    )
