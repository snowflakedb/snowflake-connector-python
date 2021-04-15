#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.auth_oauth import AuthByOAuth


def test_auth_oauth():
    """Simple OAuth test."""
    token = "oAuthToken"
    auth = AuthByOAuth(token)
    auth.authenticate(None, None, None, None, None)
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == token, body
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body
