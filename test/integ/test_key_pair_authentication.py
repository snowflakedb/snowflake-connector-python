#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

import snowflake.connector

from ..integ_helpers import drop_user
from ..randomize import random_string


@pytest.mark.skipolddriver
def test_different_key_length(is_public_test, request, conn_cnx, db_parameters):
    if is_public_test:
        pytest.skip("This test requires ACCOUNTADMIN privilege to set the public key")

    test_user = "test_different_key_length" + random_string(4)

    db_config = {"user": test_user, "timezone": "UTC"}

    request.addfinalizer(drop_user(conn_cnx, test_user))

    testcases = [2048, 4096, 8192]

    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute("use role accountadmin")
        cursor.execute(f"create user {test_user}")

        for key_length in testcases:
            private_key_der, public_key_der_encoded = generate_key_pair(key_length)
            cnx.cursor().execute(
                f"alter user {test_user} set rsa_public_key='{public_key_der_encoded}'"
            )
            db_config["private_key"] = private_key_der
            with conn_cnx(**db_config) as _:
                pass


@pytest.mark.skipolddriver
def test_multiple_key_pair(is_public_test, request, conn_cnx):
    if is_public_test:
        pytest.skip("This test requires ACCOUNTADMIN privilege to set the public key")

    test_user = "test_multiple_key_pair_" + random_string(4)

    db_config = {
        "user": test_user,
        "timezone": "UTC",
    }

    request.addfinalizer(drop_user(conn_cnx, test_user))

    private_key_one_der, public_key_one_der_encoded = generate_key_pair(2048)
    private_key_two_der, public_key_two_der_encoded = generate_key_pair(2048)

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
    use role accountadmin
    """
        )
        cnx.cursor().execute(
            f"""
    create user {test_user}
    """
        )
        cnx.cursor().execute(
            f"""
    alter user {test_user} set rsa_public_key='{public_key_one_der_encoded}'
    """
        )

    db_config["private_key"] = private_key_one_der
    with conn_cnx(**db_config) as _:
        pass

    # assert exception since different key pair is used
    db_config["private_key"] = private_key_two_der
    # although specifying password,
    # key pair authentication should used and it should fail since we don't do fall back
    db_config["password"] = "fake_password"
    with pytest.raises(snowflake.connector.errors.DatabaseError) as exec_info:
        with conn_cnx(**db_config):
            pass

    assert exec_info.value.errno == 250001
    assert exec_info.value.sqlstate == "08001"
    assert "JWT token is invalid" in exec_info.value.msg

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
    use role accountadmin
    """
        )
        cnx.cursor().execute(
            f"""
    alter user {test_user} set rsa_public_key_2='{public_key_two_der_encoded}'
    """
        )

    with conn_cnx(**db_config) as _:
        pass


def test_bad_private_key(conn_cnx):
    db_config = {
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
        "abcd",
        1234,
        b"abcd",
        dsa_private_key_der,
        encrypted_rsa_private_key_der,
    ]

    for private_key in bad_private_key_test_cases:
        db_config["private_key"] = private_key
        with pytest.raises(snowflake.connector.errors.ProgrammingError) as exec_info:
            with conn_cnx(**db_config):
                pass
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
