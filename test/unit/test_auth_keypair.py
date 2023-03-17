#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from unittest.mock import MagicMock, Mock, PropertyMock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from snowflake.connector.auth import Auth
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import SnowflakeRestful

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByKeyPair
except ImportError:
    from snowflake.connector.auth_oauth import AuthByKeyPair


def _create_mock_auth_keypair_rest_response():
    def _mock_auth_key_pair_rest_response(url, headers, body, **kwargs):
        return {
            "success": True,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    return _mock_auth_key_pair_rest_response


def test_auth_keypair():
    """Simple Key Pair test."""
    private_key_der, public_key_der_encoded = generate_key_pair(2048)
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    auth_instance = AuthByKeyPair(private_key=private_key_der)
    auth_instance.handle_timeout(
        authenticator="SNOWFLAKE_JWT",
        service_name=None,
        account=account,
        user=user,
        password=None,
    )

    # success test case
    rest = _init_rest(application, _create_mock_auth_keypair_rest_response())
    auth = Auth(rest)
    auth.authenticate(auth_instance, account, user)
    assert not rest._connection.errorhandler.called  # not error
    assert rest.token == "TOKEN"
    assert rest.master_token == "MASTER_TOKEN"


def _init_rest(application, post_requset):
    connection = MagicMock()
    connection._login_timeout = 120
    connection.login_timeout = 120
    connection._network_timeout = None
    connection.errorhandler = Mock(return_value=None)
    connection._ocsp_mode = Mock(return_value=OCSPMode.FAIL_OPEN)
    type(connection).application = PropertyMock(return_value=application)
    type(connection)._internal_application_name = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._post_request = post_requset
    return rest


def generate_key_pair(key_length):
    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=key_length
    )

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
    )

    # strip off header
    public_key_der_encoded = "".join(public_key_pem.split("\n")[1:-2])

    return private_key_der, public_key_der_encoded
