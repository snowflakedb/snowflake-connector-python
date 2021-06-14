#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import uuid
from datetime import datetime, timedelta
from os import path
from test.integ.conftest import RUNNING_AGAINST_LOCAL_SNOWFLAKE

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

import snowflake.connector


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "input_account,expected_account",
    [
        ("s3testaccount.global", "S3TESTACCOUNT.GLOBAL"),
        ("acct-with-dashes", "ACCT-WITH-DASHES"),
        ("testaccount.extra", "TESTACCOUNT"),
        ("testaccount-user.global", "TESTACCOUNT"),
        ("normalaccount", "NORMALACCOUNT"),
    ],
)
def test_get_token_from_private_key(input_account, expected_account):
    test_user = "python_test_keypair_user_" + str(uuid.uuid4()).replace("-", "_")
    current_dir = path.dirname(path.realpath(__file__))
    private_key_file_path = path.join(
        current_dir, "..", "data", "rsa_keys", "rsa_key_encrypted.p8"
    )
    private_key_password = "test"
    public_key_fingerprint = snowflake.connector.auth.get_public_key_fingerprint(
        private_key_file_path, private_key_password
    )
    # generate the jwt token
    jwt_token = snowflake.connector.auth.get_token_from_private_key(
        test_user, input_account, private_key_file_path, private_key_password
    )
    # decode the token to get its fields (iss, sub, issue time, expiration time)
    decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
    # Assert "sub" field matches {corrected account}.{user}
    assert expected_account + "." + test_user.upper() == decoded_token.get("sub")
    # Assert "iss" field matches {corrected account}.{user}.{public key fingerprint}
    assert (
        expected_account
        + "."
        + test_user.upper()
        + "."
        + public_key_fingerprint.upper()
        == decoded_token.get("iss").upper()
    )
    # Token should be valid for 24 hours. Assert that the token's expiration time is between 23 and 24 hours from now.
    assert datetime.utcnow() + timedelta(minutes=1360) < datetime.fromtimestamp(
        decoded_token.get("exp")
    )
    assert datetime.utcnow() + timedelta(minutes=1441) > datetime.fromtimestamp(
        decoded_token.get("exp")
    )


@pytest.mark.internal
@pytest.mark.skipif(
    not RUNNING_AGAINST_LOCAL_SNOWFLAKE,
    reason="connection timeouts occur when attempting to connect to this external account with automated testing",
)
def test_regionless_url_JWT_token_validity(db_parameters):

    test_user = "admin"

    db_config = {
        "account": "amoghorgurl-keypairauth_test_alias.testdns",
        "user": "admin",
        "role": "ACCOUNTADMIN",
        "timezone": "UTC",
    }

    db_config_with_pw = {
        "account": "amoghorgurl-keypairauth_test_alias.testdns",
        "user": "admin",
        "password": "Password1",
        "role": "ACCOUNTADMIN",
        "timezone": "UTC",
    }

    with snowflake.connector.connect(**db_config_with_pw) as cnx:
        with cnx.cursor() as cursor:
            cursor.execute("use role accountadmin")
            private_key_der, public_key_der_encoded = generate_key_pair(2048)
            cursor.execute(
                f"alter user {test_user} set rsa_public_key='{public_key_der_encoded}'"
            )

    db_config["private_key"] = private_key_der
    with snowflake.connector.connect(**db_config):
        pass


@pytest.mark.skipolddriver
def test_different_key_length(is_public_test, request, conn_cnx, db_parameters):
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

    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
        use role accountadmin
        """
            )
            cnx.cursor().execute(
                """
        drop user if exists {user}
        """.format(
                    user=test_user
                )
            )

    request.addfinalizer(fin)

    testcases = [2048, 4096, 8192]

    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute(
            """
    use role accountadmin
    """
        )
        cursor.execute("create user " + test_user)

        for key_length in testcases:
            private_key_der, public_key_der_encoded = generate_key_pair(key_length)

            cnx.cursor().execute(
                """
            alter user {user} set rsa_public_key='{public_key}'
            """.format(
                    user=test_user, public_key=public_key_der_encoded
                )
            )

            db_config["private_key"] = private_key_der
            with snowflake.connector.connect(**db_config) as _:
                pass


@pytest.mark.skipolddriver
def test_multiple_key_pair(is_public_test, request, conn_cnx, db_parameters):
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

    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
        use role accountadmin
        """
            )
            cnx.cursor().execute(
                """
        drop user if exists {user}
        """.format(
                    user=test_user
                )
            )

    request.addfinalizer(fin)

    private_key_one_der, public_key_one_der_encoded = generate_key_pair(2048)
    private_key_two_der, public_key_two_der_encoded = generate_key_pair(2048)

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
    use role accountadmin
    """
        )
        cnx.cursor().execute(
            """
    create user {user}
    """.format(
                user=test_user
            )
        )
        cnx.cursor().execute(
            """
    alter user {user} set rsa_public_key='{public_key}'
    """.format(
                user=test_user, public_key=public_key_one_der_encoded
            )
        )

    db_config["private_key"] = private_key_one_der
    with snowflake.connector.connect(**db_config) as _:
        pass

    # assert exception since different key pair is used
    db_config["private_key"] = private_key_two_der
    # although specifying password,
    # key pair authentication should used and it should fail since we don't do fall back
    db_config["password"] = "fake_password"
    with pytest.raises(snowflake.connector.errors.DatabaseError) as exec_info:
        snowflake.connector.connect(**db_config)

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
            """
    alter user {user} set rsa_public_key_2='{public_key}'
    """.format(
                user=test_user, public_key=public_key_two_der_encoded
            )
        )

    with snowflake.connector.connect(**db_config) as _:
        pass


def test_bad_private_key(db_parameters):
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
        "abcd",
        1234,
        b"abcd",
        dsa_private_key_der,
        encrypted_rsa_private_key_der,
    ]

    for private_key in bad_private_key_test_cases:
        db_config["private_key"] = private_key
        with pytest.raises(snowflake.connector.errors.ProgrammingError) as exec_info:
            snowflake.connector.connect(**db_config)
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
