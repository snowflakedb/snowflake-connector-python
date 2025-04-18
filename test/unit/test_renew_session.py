#!/usr/bin/env python
from __future__ import annotations

import logging
from unittest.mock import Mock, PropertyMock

from snowflake.connector.network import SnowflakeRestful

from .mock_utils import mock_connection


def test_renew_session():
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
    def fake_request_exec(**_):
        return {
            "success": True,
            "data": {
                "sessionToken": NEW_SESSION_TOKEN,
                "masterToken": NEW_MASTER_TOKEN,
            },
        }

    rest._request_exec = fake_request_exec

    rest._renew_session()
    assert not rest._connection.errorhandler.called  # no error
    assert rest.master_token == NEW_MASTER_TOKEN
    assert rest.token == NEW_SESSION_TOKEN

    # inject a fake method (failure)
    def fake_request_exec(**_):
        return {"success": False, "message": "failed to renew session", "code": 987654}

    rest._request_exec = fake_request_exec

    rest._renew_session()
    assert rest._connection.errorhandler.called  # error

    # no master token
    del rest._master_token
    rest._renew_session()
    assert rest._connection.errorhandler.called  # error


def test_mask_token_when_renew_session(caplog):
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
    def fake_request_exec(**_):
        return {
            "success": True,
            "data": {
                "sessionToken": NEW_SESSION_TOKEN,
                "masterToken": NEW_MASTER_TOKEN,
            },
        }

    rest._request_exec = fake_request_exec

    # no secrets recorded when renew succeed
    rest._renew_session()
    assert "new_session_token" not in caplog.text
    assert "new_master_token" not in caplog.text
    assert "old_session_token" not in caplog.text
    assert "old_master_token" not in caplog.text

    def fake_request_exec(**_):
        return {"success": False, "message": "failed to renew session", "code": 987654}

    rest._request_exec = fake_request_exec

    # no secrets recorded when renew failed
    rest._renew_session()
    assert "new_session_token" not in caplog.text
    assert "new_master_token" not in caplog.text
    assert "old_session_token" not in caplog.text
    assert "old_master_token" not in caplog.text
