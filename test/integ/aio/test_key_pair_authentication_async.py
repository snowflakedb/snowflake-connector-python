#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import uuid

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

import snowflake.connector
import snowflake.connector.aio


async def test_different_key_length(is_public_test, request, conn_cnx, db_parameters):
    if is_public_test:
        pytest.skip("This test requires ACCOUNTADMIN privilege to set the public key")

    test_user = "python_test_keypair_user_" + str(uuid.uuid4()).replace("-", "_")

    db_config = {
        "protocol": db_parameters["protocol"],
        "account": db_parameters["account"],
        "user": test_user,
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "database": db_parameters["database"],
        "schema": db_parameters["schema"],
        "timezone": "UTC",
    }

    async def finalizer():
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
        use role accountadmin
        """
            )
            await cnx.cursor().execute(
                """
        drop user if exists {user}
        """.format(
                    user=test_user
                )
            )

    def fin():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(finalizer())

    request.addfinalizer(fin)

    testcases = [2048, 4096, 8192]

    async with conn_cnx() as cnx:
        cursor = cnx.cursor()
        await cursor.execute(
            """
    use role accountadmin
    """
        )
        await cursor.execute("create user " + test_user)

        for key_length in testcases:
            private_key_der, public_key_der_encoded = generate_key_pair(key_length)

            await cnx.cursor().execute(
                """
            alter user {user} set rsa_public_key='{public_key}'
            """.format(
                    user=test_user, public_key=public_key_der_encoded
                )
            )

            db_config["private_key"] = private_key_der
            async with snowflake.connector.aio.SnowflakeConnection(**db_config) as _:
                pass


@pytest.mark.skipolddriver
async def test_multiple_key_pair(is_public_test, request, conn_cnx, db_parameters):
    if is_public_test:
        pytest.skip("This test requires ACCOUNTADMIN privilege to set the public key")

    test_user = "python_test_keypair_user_" + str(uuid.uuid4()).replace("-", "_")

    db_config = {
        "protocol": db_parameters["protocol"],
        "account": db_parameters["account"],
        "user": test_user,
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "database": db_parameters["database"],
        "schema": db_parameters["schema"],
        "timezone": "UTC",
    }

    async def finalizer():
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
        use role accountadmin
        """
            )
            await cnx.cursor().execute(
                """
        drop user if exists {user}
        """.format(
                    user=test_user
                )
            )

    def fin():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(finalizer())

    request.addfinalizer(fin)

    private_key_one_der, public_key_one_der_encoded = generate_key_pair(2048)
    private_key_two_der, public_key_two_der_encoded = generate_key_pair(2048)

    async with conn_cnx() as cnx:
        await cnx.cursor().execute(
            """
    use role accountadmin
    """
        )
        await cnx.cursor().execute(
            """
    create user {user}
    """.format(
                user=test_user
            )
        )
        await cnx.cursor().execute(
            """
    alter user {user} set rsa_public_key='{public_key}'
    """.format(
                user=test_user, public_key=public_key_one_der_encoded
            )
        )

    db_config["private_key"] = private_key_one_der
    async with snowflake.connector.aio.SnowflakeConnection(**db_config) as _:
        pass

    # assert exception since different key pair is used
    db_config["private_key"] = private_key_two_der
    # although specifying password,
    # key pair authentication should used and it should fail since we don't do fall back
    db_config["password"] = "fake_password"
    with pytest.raises(snowflake.connector.errors.DatabaseError) as exec_info:
        await snowflake.connector.aio.SnowflakeConnection(**db_config).connect()

    assert exec_info.value.errno == 250001
    assert exec_info.value.sqlstate == "08001"
    assert "JWT token is invalid" in exec_info.value.msg

    async with conn_cnx() as cnx:
        await cnx.cursor().execute(
            """
    use role accountadmin
    """
        )
        await cnx.cursor().execute(
            """
    alter user {user} set rsa_public_key_2='{public_key}'
    """.format(
                user=test_user, public_key=public_key_two_der_encoded
            )
        )

    async with snowflake.connector.aio.SnowflakeConnection(**db_config) as _:
        pass


async def test_bad_private_key(db_parameters):
    db_config = {
        "protocol": db_parameters["protocol"],
        "account": db_parameters["account"],
        "user": db_parameters["user"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "database": db_parameters["database"],
        "schema": db_parameters["schema"],
        "timezone": "UTC",
    }

    dsa_private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    dsa_private_key_der = dsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encrypted_rsa_private_key_der = rsa.generate_private_key(
        key_size=2048, public_exponent=65537, backend=default_backend()
    ).private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"abcd"),
    )

    bad_private_key_test_cases = [
        b"abcd",
        dsa_private_key_der,
        encrypted_rsa_private_key_der,
    ]

    for private_key in bad_private_key_test_cases:
        db_config["private_key"] = private_key
        with pytest.raises(snowflake.connector.errors.ProgrammingError) as exec_info:
            await snowflake.connector.aio.SnowflakeConnection(**db_config).connect()
        assert exec_info.value.errno == 251008


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