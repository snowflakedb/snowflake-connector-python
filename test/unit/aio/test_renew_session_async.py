#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from test.unit.mock_utils import mock_connection
from unittest.mock import Mock, PropertyMock

from snowflake.connector.aio._network import SnowflakeRestful


async def test_renew_session():
    OLD_SESSION_TOKEN = "old_session_token"
    OLD_MASTER_TOKEN = "old_master_token"
    NEW_SESSION_TOKEN = "new_session_token"
    NEW_MASTER_TOKEN = "new_master_token"
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)
    type(connection)._probe_connection = PropertyMock(return_value=False)

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._token = OLD_SESSION_TOKEN
    rest._master_token = OLD_MASTER_TOKEN

    # inject a fake method (success)
    async def fake_request_exec(**_):
        return {
            "success": True,
            "data": {
                "sessionToken": NEW_SESSION_TOKEN,
                "masterToken": NEW_MASTER_TOKEN,
            },
        }

    rest._request_exec = fake_request_exec

    await rest._renew_session()
    assert not rest._connection.errorhandler.called  # no error
    assert rest.master_token == NEW_MASTER_TOKEN
    assert rest.token == NEW_SESSION_TOKEN

    # inject a fake method (failure)
    async def fake_request_exec(**_):
        return {"success": False, "message": "failed to renew session", "code": 987654}

    rest._request_exec = fake_request_exec

    await rest._renew_session()
    assert rest._connection.errorhandler.called  # error

    # no master token
    del rest._master_token
    await rest._renew_session()
    assert rest._connection.errorhandler.called  # error


async def test_mask_token_when_renew_session(caplog):
    caplog.set_level(logging.DEBUG)
    OLD_SESSION_TOKEN = "old_session_token"
    OLD_MASTER_TOKEN = "old_master_token"
    NEW_SESSION_TOKEN = "new_session_token"
    NEW_MASTER_TOKEN = "new_master_token"
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)
    type(connection)._probe_connection = PropertyMock(return_value=False)

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._token = OLD_SESSION_TOKEN
    rest._master_token = OLD_MASTER_TOKEN

    # inject a fake method (success)
    async def fake_request_exec(**_):
        return {
            "success": True,
            "data": {
                "sessionToken": NEW_SESSION_TOKEN,
                "masterToken": NEW_MASTER_TOKEN,
            },
        }

    rest._request_exec = fake_request_exec

    # no secrets recorded when renew succeed
    await rest._renew_session()
    assert "new_session_token" not in caplog.text
    assert "new_master_token" not in caplog.text
    assert "old_session_token" not in caplog.text
    assert "old_master_token" not in caplog.text

    async def fake_request_exec(**_):
        return {"success": False, "message": "failed to renew session", "code": 987654}

    rest._request_exec = fake_request_exec

    # no secrets recorded when renew failed
    await rest._renew_session()
    assert "new_session_token" not in caplog.text
    assert "new_master_token" not in caplog.text
    assert "old_session_token" not in caplog.text
    assert "old_master_token" not in caplog.text
