#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import snowflake.connector


def test_session_parameters(db_parameters):
    """Sets the session parameters in connection time."""
    connection = snowflake.connector.connect(
        protocol=db_parameters['protocol'],
        account=db_parameters['account'],
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        session_parameters={
            'TIMEZONE': 'UTC'
        }
    )
    ret = connection.cursor().execute(
        "show parameters like 'TIMEZONE'").fetchone()
    assert ret[1] == 'UTC'


def test_client_session_keep_alive(db_parameters):
    """Tests client_session_keep_alive setting.

    Ensures that client's explicit config for client_session_keep_alive
    session parameter is always honored and given higher precedence over
    user and account level backend configuration.
    """
    # Ensure backend parameter is set to False
    set_backend_client_session_keep_alive(db_parameters, False)
    connection = create_client_connection(db_parameters, True)

    ret = connection.cursor().execute(
        "show parameters like 'CLIENT_SESSION_KEEP_ALIVE'").fetchone()
    assert ret[1] == 'true'
    connection.close()

    # Set backend parameter to True
    set_backend_client_session_keep_alive(db_parameters, True)

    # Set session parameter to False
    connection = create_client_connection(db_parameters, False)
    ret = connection.cursor().execute(
        "show parameters like 'CLIENT_SESSION_KEEP_ALIVE'").fetchone()
    assert ret[1] == 'false'
    connection.close()

    # Set session parameter to None backend parameter continues to be True
    connection = create_client_connection(db_parameters, None)
    ret = connection.cursor().execute(
        "show parameters like 'CLIENT_SESSION_KEEP_ALIVE'").fetchone()
    assert ret[1] == 'true'
    connection.close()


def create_client_connection(db_parameters: object, val: bool) -> object:
    """Create connection with client session keep alive set to specific value."""
    connection = snowflake.connector.connect(
        protocol=db_parameters['protocol'],
        account=db_parameters['account'],
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        client_session_keep_alive=val
    )
    return connection


def set_backend_client_session_keep_alive(db_parameters: object, val: bool) -> None:
    """Set both at Account level and User level."""
    connection = snowflake.connector.connect(
        protocol=db_parameters['sf_protocol'],
        account=db_parameters['sf_account'],
        user=db_parameters['sf_user'],
        password=db_parameters['sf_password'],
        host=db_parameters['sf_host'],
        port=db_parameters['sf_port']
    )
    query = "alter account {} set CLIENT_SESSION_KEEP_ALIVE={}".format(
        db_parameters['account'], str(val))
    connection.cursor().execute(query)

    query = "alter user {}.{} set CLIENT_SESSION_KEEP_ALIVE={}".format(
                    db_parameters['account'], db_parameters['user'], str(val))
    connection.cursor().execute(query)
