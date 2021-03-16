#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import json
import os

import pytest
from mock import Mock, patch

import snowflake.connector
from snowflake.connector.compat import IS_LINUX
from snowflake.connector.errors import DatabaseError

try:
    from snowflake.connector.compat import IS_MACOS  # NOQA
except ImportError:
    import platform

    IS_MACOS = platform.system() == "Darwin"
try:
    from snowflake.connector.auth import delete_temporary_credential  # NOQA
except ImportError:
    delete_temporary_credential = None

MFA_TOKEN = "MFATOKEN"


# Although this is an unit test, we put it under test/integ/sso, since it needs keyring package installed
@pytest.mark.skipif(
    delete_temporary_credential is None,
    reason="delete_temporary_credential is not available.",
)
@patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_mfa_cache(mockSnowflakeRestfulPostRequest):
    """Connects with (username, pwd, mfa) mock."""
    os.environ["SF_TEMPORARY_CREDENTIAL_CACHE_DIR"] = os.getenv(
        "WORKSPACE", os.path.expanduser("~")
    )

    LOCAL_CACHE = dict()

    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_post_req_cnt
        ret = None
        body = json.loads(json_body)
        if mock_post_req_cnt == 0:
            # issue MFA token for a succeeded login
            assert (
                body["data"]["SESSION_PARAMETERS"].get("CLIENT_REQUEST_MFA_TOKEN")
                is True
            )
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "TOKEN",
                    "masterToken": "MASTER_TOKEN",
                    "mfaToken": "MFA_TOKEN",
                },
            }
        elif mock_post_req_cnt == 2:
            # check associated mfa token and issue a new mfa token
            # note: Normally, backend doesn't issue a new mfa token in this case, we do it here only to test
            # whether the driver can replace the old token when server provides a new token
            assert (
                body["data"]["SESSION_PARAMETERS"].get("CLIENT_REQUEST_MFA_TOKEN")
                is True
            )
            assert body["data"]["TOKEN"] == "MFA_TOKEN"
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "NEW_TOKEN",
                    "masterToken": "NEW_MASTER_TOKEN",
                    "mfaToken": "NEW_MFA_TOKEN",
                },
            }
        elif mock_post_req_cnt == 4:
            # check new mfa token
            assert (
                body["data"]["SESSION_PARAMETERS"].get("CLIENT_REQUEST_MFA_TOKEN")
                is True
            )
            assert body["data"]["TOKEN"] == "NEW_MFA_TOKEN"
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "NEW_TOKEN",
                    "masterToken": "NEW_MASTER_TOKEN",
                },
            }
        elif mock_post_req_cnt == 6:
            # mock a failed log in
            ret = {"success": False, "message": None, "data": {}}
        elif mock_post_req_cnt == 7:
            assert (
                body["data"]["SESSION_PARAMETERS"].get("CLIENT_REQUEST_MFA_TOKEN")
                is True
            )
            assert "TOKEN" not in body["data"]
            ret = {
                "success": True,
                "data": {"token": "TOKEN", "masterToken": "MASTER_TOKEN"},
            }
        elif mock_post_req_cnt in [1, 3, 5, 8]:
            # connection.close()
            ret = {"success": True}
        mock_post_req_cnt += 1
        return ret

    def mock_del_password(system, user):
        LOCAL_CACHE.pop(system + user, None)

    def mock_set_password(system, user, pwd):
        LOCAL_CACHE[system + user] = pwd

    def mock_get_password(system, user):
        return LOCAL_CACHE.get(system + user, None)

    global mock_post_req_cnt
    mock_post_req_cnt = 0

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    def test_body(conn_cfg):
        delete_temporary_credential(
            host=conn_cfg["host"], user=conn_cfg["user"], cred_type=MFA_TOKEN
        )

        # first connection, no mfa token cache
        con = snowflake.connector.connect(**conn_cfg)
        assert con._rest.token == "TOKEN"
        assert con._rest.master_token == "MASTER_TOKEN"
        assert con._rest.mfa_token == "MFA_TOKEN"
        con.close()

        # second connection that uses the mfa token issued for first connection to login
        con = snowflake.connector.connect(**conn_cfg)
        assert con._rest.token == "NEW_TOKEN"
        assert con._rest.master_token == "NEW_MASTER_TOKEN"
        assert con._rest.mfa_token == "NEW_MFA_TOKEN"
        con.close()

        # third connection which is expected to login with new mfa token
        con = snowflake.connector.connect(**conn_cfg)
        assert con._rest.mfa_token is None
        con.close()

        with pytest.raises(DatabaseError):
            # A failed login will be forced by a mocked response for this connection
            # Under authentication failed exception, mfa cache is expected to be cleaned up
            con = snowflake.connector.connect(**conn_cfg)

        # no mfa cache token should be sent at this connection
        con = snowflake.connector.connect(**conn_cfg)
        con.close()

    conn_cfg = {
        "account": "testaccount",
        "user": "testuser",
        "password": "testpwd",
        "authenticator": "username_password_mfa",
        "host": "testaccount.snowflakecomputing.com",
    }
    if IS_LINUX:
        conn_cfg["client_request_mfa_token"] = True

    if IS_MACOS:
        with patch(
            "keyring.delete_password", Mock(side_effect=mock_del_password)
        ), patch("keyring.set_password", Mock(side_effect=mock_set_password)), patch(
            "keyring.get_password", Mock(side_effect=mock_get_password)
        ):
            test_body(conn_cfg)
    else:
        test_body(conn_cfg)
