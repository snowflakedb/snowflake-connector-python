from __future__ import annotations

import pathlib

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import snowflake.connector.errors
from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.sqlstate import (
    SQLSTATE_AUTHORIZATION_FAILURE,
    SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
)

from ...test_utils.wiremock.wiremock_utils import WiremockClient

KEYPAIR_WIREMOCK_DIR = (
    pathlib.Path(__file__).parent.parent.parent
    / "data"
    / "wiremock"
    / "mappings"
    / "auth"
    / "keypair"
)


def _generate_private_key_der() -> bytes:
    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.mark.skipolddriver
async def test_jwt_credential_rejection_surfaces_server_errno_and_sqlstate_authorization_failure(
    wiremock_client: WiremockClient,
) -> None:
    """Server JWT rejection codes (CREDENTIAL_REJECTION_GS_CODES) surface the server's
    errno and use SQLSTATE 28000 instead of the old hardcoded 250001/08001."""
    wiremock_client.import_mapping(KEYPAIR_WIREMOCK_DIR / "jwt_token_invalid.json")

    with pytest.raises(snowflake.connector.errors.DatabaseError) as exc_info:
        connection = SnowflakeConnection(
            authenticator="SNOWFLAKE_JWT",
            private_key=_generate_private_key_der(),
            user="testUser",
            account="testAccount",
            protocol="http",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )
        await connection.connect()

    assert exc_info.value.errno == 390144
    assert exc_info.value.sqlstate == SQLSTATE_AUTHORIZATION_FAILURE


@pytest.mark.skipolddriver
async def test_jwt_non_credential_rejection_uses_sqlstate_connection_not_established(
    wiremock_client: WiremockClient,
) -> None:
    """Non-credential-rejection error codes still use SQLSTATE 08001."""
    wiremock_client.import_mapping(
        KEYPAIR_WIREMOCK_DIR / "jwt_generic_login_error.json"
    )

    with pytest.raises(snowflake.connector.errors.DatabaseError) as exc_info:
        connection = SnowflakeConnection(
            authenticator="SNOWFLAKE_JWT",
            private_key=_generate_private_key_der(),
            user="testUser",
            account="testAccount",
            protocol="http",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )
        await connection.connect()

    assert exc_info.value.errno == 390401
    assert exc_info.value.sqlstate == SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
