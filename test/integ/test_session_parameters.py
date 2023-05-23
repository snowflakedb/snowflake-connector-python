#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

import snowflake.connector

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

try:  # pragma: no cover
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
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


@pytest.mark.internal
def test_htap_optimizations(db_parameters: object, conn_cnx) -> None:
    random_prefix = random_string(5, "test_prefix").lower()
    test_wh = f"{random_prefix}_wh"
    test_db = f"{random_prefix}_db"
    test_schema = f"{random_prefix}_schema"

    with conn_cnx("admin") as admin_cnx:
        try:
            admin_cnx.cursor().execute(f"CREATE WAREHOUSE IF NOT EXISTS {test_wh}")
            admin_cnx.cursor().execute(f"USE WAREHOUSE {test_wh}")
            admin_cnx.cursor().execute(f"CREATE DATABASE IF NOT EXISTS {test_db}")
            admin_cnx.cursor().execute(f"CREATE SCHEMA IF NOT EXISTS {test_schema}")
            query = f"alter account {db_parameters['sf_account']} set ENABLE_SNOW_654741_FOR_TESTING=true"
            admin_cnx.cursor().execute(query)

            # assert wh, db, schema match conn params
            assert admin_cnx._warehouse.lower() == test_wh
            assert admin_cnx._database.lower() == test_db
            assert admin_cnx._schema.lower() == test_schema

            # alter session set TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FFTZH'
            admin_cnx.cursor().execute(
                "alter session set TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FFTZH'"
            )

            # create or replace table
            admin_cnx.cursor().execute(
                "create or replace temp table testtable1 (cola string, colb int)"
            )
            # insert into table 3 vals
            admin_cnx.cursor().execute(
                "insert into testtable1 values ('row1', 1), ('row2', 2), ('row3', 3)"
            )
            # select * from table
            ret = admin_cnx.cursor().execute("select * from testtable1").fetchall()
            # assert we get 3 results
            assert len(ret) == 3

            # assert wh, db, schema
            assert admin_cnx._warehouse.lower() == test_wh
            assert admin_cnx._database.lower() == test_db
            assert admin_cnx._schema.lower() == test_schema

            assert (
                admin_cnx._session_parameters["TIMESTAMP_OUTPUT_FORMAT"]
                == "YYYY-MM-DD HH24:MI:SS.FFTZH"
            )

            # alter session unset TIMESTAMP_OUTPUT_FORMAT
            admin_cnx.cursor().execute("alter session unset TIMESTAMP_OUTPUT_FORMAT")
        finally:
            # alter account unset ENABLE_SNOW_654741_FOR_TESTING
            query = f"alter account {db_parameters['sf_account']} unset ENABLE_SNOW_654741_FOR_TESTING"
            admin_cnx.cursor().execute(query)
            admin_cnx.cursor().execute(f"DROP SCHEMA IF EXISTS {test_schema}")
            admin_cnx.cursor().execute(f"DROP DATABASE IF EXISTS {test_db}")
            admin_cnx.cursor().execute(f"DROP WAREHOUSE IF EXISTS {test_wh}")
