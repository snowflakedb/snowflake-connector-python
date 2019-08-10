#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import rsa

import snowflake.connector

NO_ACCOUNTADMIN_PRIV = os.getenv('TRAVIS') == 'true' or \
                       os.getenv('APPVEYOR') == 'True' or \
                       os.getenv('sf_account') == 'testaccount5'


@pytest.mark.skipif(
    NO_ACCOUNTADMIN_PRIV,
    reason="Change user's public key requires accountadmin privilege"
)
def test_different_key_length(request, conn_cnx, db_parameters):
    db_config = {
        'protocol': db_parameters['protocol'],
        'account': db_parameters['account'],
        'user': db_parameters['user'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'database': db_parameters['database'],
        'schema': db_parameters['schema'],
        'timezone': 'UTC',
    }

    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute("""
        use role accountadmin
        """)
            cnx.cursor().execute("""
        alter user {user} unset rsa_public_key
        """.format(user=db_parameters['user']))

    request.addfinalizer(fin)

    testcases = [2048, 4096, 8192]

    for key_length in testcases:
        private_key_der, public_key_der_encoded = generate_key_pair(key_length)

        with conn_cnx() as cnx:
            cnx.cursor().execute("""
    use role accountadmin
    """)
            cnx.cursor().execute("""
    alter user {user} set rsa_public_key='{public_key}'
    """.format(user=db_parameters['user'], public_key=public_key_der_encoded))

        db_config['private_key'] = private_key_der
        snowflake.connector.connect(**db_config)


@pytest.mark.skipif(
    NO_ACCOUNTADMIN_PRIV,
    reason="Change user's public key requires accountadmin privilege"
)
def test_multiple_key_pair(request, conn_cnx, db_parameters):
    db_config = {
        'protocol': db_parameters['protocol'],
        'account': db_parameters['account'],
        'user': db_parameters['user'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'database': db_parameters['database'],
        'schema': db_parameters['schema'],
        'timezone': 'UTC',
    }

    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute("""
        use role accountadmin
        """)
            cnx.cursor().execute("""
        alter user {user} unset rsa_public_key
        """.format(user=db_parameters['user']))
            cnx.cursor().execute("""
        alter user {user} unset rsa_public_key_2
        """.format(user=db_parameters['user']))

    request.addfinalizer(fin)

    private_key_one_der, public_key_one_der_encoded = generate_key_pair(2048)
    private_key_two_der, public_key_two_der_encoded = generate_key_pair(2048)

    with conn_cnx() as cnx:
        cnx.cursor().execute("""
    use role accountadmin
    """)
        cnx.cursor().execute("""
    alter user {user} set rsa_public_key='{public_key}'
    """.format(user=db_parameters['user'],
               public_key=public_key_one_der_encoded))

    db_config['private_key'] = private_key_one_der
    snowflake.connector.connect(**db_config)

    # assert exception since different key pair is used
    db_config['private_key'] = private_key_two_der
    # although specifying password,
    # key pair authentication should used and it should fail since we don't do fall back
    db_config['password'] = 'fake_password'
    with pytest.raises(snowflake.connector.errors.DatabaseError) as exec_info:
        snowflake.connector.connect(**db_config)

    assert (exec_info.value.errno == 250001)
    assert (exec_info.value.sqlstate == '08001')
    assert ("JWT token is invalid" in exec_info.value.msg)

    with conn_cnx() as cnx:
        cnx.cursor().execute("""
    use role accountadmin
    """)
        cnx.cursor().execute("""
    alter user {user} set rsa_public_key_2='{public_key}'
    """.format(user=db_parameters['user'],
               public_key=public_key_two_der_encoded))
    snowflake.connector.connect(**db_config)


def test_bad_private_key(db_parameters):
    db_config = {
        'protocol': db_parameters['protocol'],
        'account': db_parameters['account'],
        'user': db_parameters['user'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'database': db_parameters['database'],
        'schema': db_parameters['schema'],
        'timezone': 'UTC',
    }

    dsa_private_key = dsa.generate_private_key(key_size=2048,
                                               backend=default_backend())
    dsa_private_key_der = dsa_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    encrypted_rsa_private_key_der = rsa.generate_private_key(key_size=2048,
                                                             public_exponent=65537,
                                                             backend=default_backend()) \
        .private_bytes(encoding=serialization.Encoding.DER,
                       format=serialization.PrivateFormat.PKCS8,
                       encryption_algorithm=serialization.BestAvailableEncryption(
                           b'abcd'))

    bad_private_key_test_cases = ["abcd", 1234, b'abcd', dsa_private_key_der,
                                  encrypted_rsa_private_key_der]

    for private_key in bad_private_key_test_cases:
        db_config['private_key'] = private_key
        with pytest.raises(
                snowflake.connector.errors.ProgrammingError) as exec_info:
            snowflake.connector.connect(**db_config)
        assert (exec_info.value.errno == 251008)


def generate_key_pair(key_length):
    private_key = rsa.generate_private_key(backend=default_backend(),
                                           public_exponent=65537,
                                           key_size=key_length)

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) \
        .decode("utf-8")

    # strip off header
    public_key_der_encoded = ''.join(public_key_pem.split('\n')[1:-2])

    return private_key_der, public_key_der_encoded
