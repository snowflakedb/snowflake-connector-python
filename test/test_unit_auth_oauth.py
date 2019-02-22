#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.auth_oauth import AuthByOAuth
from snowflake.connector.compat import PY2
from snowflake.connector.network import (
    SnowflakeRestful, CLIENT_VERSION, CLIENT_NAME)

if PY2:
    from mock import MagicMock, Mock, PropertyMock
else:
    from unittest.mock import MagicMock, Mock, PropertyMock


def test_auth_oauth():
    """ Simple OAuth test."""
    token = "oAuthToken"
    auth = AuthByOAuth(token)
    auth.authenticate(None, None, None, None, None)
    body = {'data':{}}
    auth.update_body(body)
    assert body['data']['TOKEN'] == token, body
    assert body['data']['AUTHENTICATOR'] == 'OAUTH', body
