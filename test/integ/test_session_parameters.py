#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

import snowflake.connector

try:  # pragma: no cover
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


def test_session_parameters(db_parameters):
    """Sets the session parameters in connection time."""
    connection = snowflake.connector.connect(
        protocol=db_parameters["protocol"],
        account=db_parameters["account"],
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        session_parameters={"TIMEZONE": "UTC"},
    )
    ret = connection.cursor().execute("show parameters like 'TIMEZONE'").fetchone()
    assert ret[1] == "UTC"


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin required to setup parameter.",
)
def test_client_session_keep_alive(db_parameters, conn_cnx):
    """Tests client_session_keep_alive setting.

    Ensures that client's explicit config for client_session_keep_alive
    session parameter is always honored and given higher precedence over
    user and account level backend configuration.
    """
    admin_cnxn = snowflake.connector.connect(
        protocol=db_parameters["sf_protocol"],
        account=db_parameters["sf_account"],
        user=db_parameters["sf_user"],
        password=db_parameters["sf_password"],
        host=db_parameters["sf_host"],
        port=db_parameters["sf_port"],
    )

    # Ensure backend parameter is set to False
    set_backend_client_session_keep_alive(db_parameters, admin_cnxn, False)
    with conn_cnx(client_session_keep_alive=True) as connection:
        ret = (
            connection.cursor()
            .execute("show parameters like 'CLIENT_SESSION_KEEP_ALIVE'")
            .fetchone()
        )
        assert ret[1] == "true"

    # Set backend parameter to True
    set_backend_client_session_keep_alive(db_parameters, admin_cnxn, True)

    # Set session parameter to False
    with conn_cnx(client_session_keep_alive=False) as connection:
        ret = (
            connection.cursor()
            .execute("show parameters like 'CLIENT_SESSION_KEEP_ALIVE'")
            .fetchone()
        )
        assert ret[1] == "false"

    # Set session parameter to None backend parameter continues to be True
    with conn_cnx(client_session_keep_alive=None) as connection:
        ret = (
            connection.cursor()
            .execute("show parameters like 'CLIENT_SESSION_KEEP_ALIVE'")
            .fetchone()
        )
        assert ret[1] == "true"

    admin_cnxn.close()


def create_client_connection(db_parameters: object, val: bool) -> object:
    """Create connection with client session keep alive set to specific value."""
    connection = snowflake.connector.connect(
        protocol=db_parameters["protocol"],
        account=db_parameters["account"],
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        client_session_keep_alive=val,
    )
    return connection


def set_backend_client_session_keep_alive(
    db_parameters: object, admin_cnx: object, val: bool
) -> None:
    """Set both at Account level and User level."""
    query = "alter account {} set CLIENT_SESSION_KEEP_ALIVE={}".format(
        db_parameters["account"], str(val)
    )
    admin_cnx.cursor().execute(query)

    query = "alter user {}.{} set CLIENT_SESSION_KEEP_ALIVE={}".format(
        db_parameters["account"], db_parameters["user"], str(val)
    )
    admin_cnx.cursor().execute(query)
