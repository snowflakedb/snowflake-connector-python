#!/usr/bin/env python
from __future__ import annotations

from test.helpers import apply_auth_class_update_body, create_mock_auth_body
from unittest.mock import Mock, PropertyMock, patch

import pytest
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


@pytest.mark.parametrize("authenticator", ["SNOWFLAKE_JWT", "snowflake_jwt"])
def test_auth_keypair(authenticator):
    """Simple Key Pair test."""
    private_key_der, public_key_der_encoded = generate_key_pair(2048)
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    auth_instance = AuthByKeyPair(private_key=private_key_der)
    auth_instance._retry_ctx.set_start_time()
    auth_instance.handle_timeout(
        authenticator=authenticator,
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


def test_auth_keypair_with_passphrase():
    """Simple Key Pair test with passphrase."""

    passphrase = b"test"
    private_key_der, public_key_der_encoded = generate_key_pair(
        2048,
        passphrase=passphrase,
    )
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    auth_instance = AuthByKeyPair(
        private_key=private_key_der,
        private_key_passphrase=passphrase,
    )
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


def test_auth_keypair_encrypted_without_passphrase():
    """Test that encrypted key without passphrase raises error with helpful message."""
    from snowflake.connector.errors import ProgrammingError

    passphrase = b"test"
    private_key_der, _ = generate_key_pair(
        2048,
        passphrase=passphrase,
    )
    account = "testaccount"
    user = "testuser"

    # Create auth instance without providing passphrase for encrypted key
    auth_instance = AuthByKeyPair(private_key=private_key_der)

    with raises(ProgrammingError) as ex:
        auth_instance.prepare(account=account, user=user)

    # Verify the error message mentions the passphrase option
    assert "private_key_passphrase" in str(ex.value)


def test_auth_keypair_wrong_passphrase():
    """Test that wrong passphrase raises error."""
    from snowflake.connector.errors import ProgrammingError

    passphrase = b"correct_passphrase"
    private_key_der, _ = generate_key_pair(
        2048,
        passphrase=passphrase,
    )
    account = "testaccount"
    user = "testuser"

    # Create auth instance with wrong passphrase
    auth_instance = AuthByKeyPair(
        private_key=private_key_der,
        private_key_passphrase=b"wrong_passphrase",
    )

    with raises(ProgrammingError) as ex:
        auth_instance.prepare(account=account, user=user)

    # Verify the error mentions the private key loading failure
    assert "Failed to load private key" in str(ex.value)


def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    private_key_der, _ = generate_key_pair(2048)
    auth_class = AuthByKeyPair(private_key=private_key_der)

    req_body_before = create_mock_auth_body()
    req_body_after = apply_auth_class_update_body(auth_class, req_body_before)

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


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

    for bad_private_key in (1234, Bad()):
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
    connection.cert_revocation_check_mode = "TEST_CRL_MODE"
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


def generate_key_pair(key_length: int, *, passphrase: bytes | None = None):
    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=key_length
    )

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        ),
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


@pytest.mark.skipolddriver
def test_expand_tilde(monkeypatch, tmp_path):
    """Test tilde expansion on both Windows and Linux/Mac"""
    import sys
    from pathlib import Path

    from snowflake.connector.util_text import expand_tilde

    mock_home = tmp_path / "test_home"
    mock_home.mkdir()

    if sys.platform == "win32":
        # Windows uses USERPROFILE (and falls back to HOMEDRIVE+HOMEPATH)
        # also set HOME for consistency
        monkeypatch.setenv("USERPROFILE", str(mock_home))
        monkeypatch.setenv("HOME", str(mock_home))
        expected_expanded = str(Path(mock_home) / "key.p8")
    else:
        # Linux and Mac, uses HOME
        monkeypatch.setenv("HOME", str(mock_home))
        expected_expanded = str(Path(mock_home) / "key.p8")

    absolute_path = "/path/to/key.p8"
    assert expand_tilde(absolute_path) == absolute_path

    # this should be expanded properly
    tilde_path = "~/key.p8"
    result = expand_tilde(tilde_path)
    assert Path(result) == Path(expected_expanded)

    # without USERPROFILE/HOME. should still resolve per fallback mechanism
    if sys.platform == "win32":
        monkeypatch.delenv("USERPROFILE", raising=False)
        monkeypatch.delenv("HOME", raising=False)
        result = expand_tilde("~/key.p8")
        assert isinstance(result, str)
    else:
        monkeypatch.delenv("HOME", raising=False)
        result = expand_tilde("~/key.p8")
        # should still resolve from /etc/passwd
        # checking if it's a string which starts with / , not the exact path
        assert result.startswith("/")

    # non-string inputs
    assert expand_tilde(None) is None
    assert expand_tilde(123) == 123
