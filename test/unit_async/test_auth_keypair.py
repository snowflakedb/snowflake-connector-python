#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from unittest.mock import Mock, PropertyMock, patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key
from pytest import raises

from snowflake.connector.auth import Auth
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import SnowflakeRestful

from .mock_utils import mock_connection

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
    auth_instance._retry_ctx.set_start_time()
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


def test_auth_keypair_abc():
    """Simple Key Pair test using abstraction layer."""
    private_key_der, public_key_der_encoded = generate_key_pair(2048)
    application = "testapplication"
    account = "testaccount"
    user = "testuser"

    private_key = load_der_private_key(
        data=private_key_der,
        password=None,
        backend=default_backend(),
    )

    assert isinstance(private_key, RSAPrivateKey)

    auth_instance = AuthByKeyPair(private_key=private_key)
    auth_instance._retry_ctx.set_start_time()
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


def test_auth_keypair_bad_type():
    """Simple Key Pair test using abstraction layer."""
    account = "testaccount"
    user = "testuser"

    class Bad:
        pass

    for bad_private_key in ("abcd", 1234, Bad()):
        auth_instance = AuthByKeyPair(private_key=bad_private_key)
        with raises(TypeError) as ex:
            auth_instance.prepare(account=account, user=user)
        assert str(type(bad_private_key)) in str(ex)


@patch("snowflake.connector.auth.keypair.AuthByKeyPair.prepare")
def test_renew_token(mockPrepare):
    private_key_der, _ = generate_key_pair(2048)
    auth_instance = AuthByKeyPair(private_key=private_key_der)

    # force renew condition to be met
    auth_instance._retry_ctx.set_start_time()
    auth_instance._jwt_timeout = 0
    account = "testaccount"
    user = "testuser"

    auth_instance.handle_timeout(
        authenticator="SNOWFLAKE_JWT",
        service_name=None,
        account=account,
        user=user,
        password=None,
    )

    assert mockPrepare.called


def _init_rest(application, post_requset):
    connection = mock_connection()
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
