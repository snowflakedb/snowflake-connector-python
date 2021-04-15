#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

# This test requires the SSO and Snowflake admin connection parameters.
#
# CONNECTION_PARAMETERS_SSO = {
#     'account': 'testaccount',
#     'user': 'qa@snowflakecomputing.com',
#     'protocol': 'http',
#     'host': 'testaccount.reg.snowflakecomputing.com',
#     'port': '8082',
#     'authenticator': 'externalbrowser',
#     'timezone': 'UTC',
# }
#
# CONNECTION_PARAMETERS_ADMIN = { ... Snowflake admin ... }

import os
import sys

import pytest

import snowflake.connector

try:
    from snowflake.connector.auth import delete_temporary_credential
except ImportError:
    delete_temporary_credential = None

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from parameters import CONNECTION_PARAMETERS_SSO
except ImportError:
    CONNECTION_PARAMETERS_SSO = {}

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

ID_TOKEN = "ID_TOKEN"


@pytest.fixture
def token_validity_test_values(request):
    with snowflake.connector.connect(**CONNECTION_PARAMETERS_ADMIN) as cnx:
        cnx.cursor().execute(
            """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=60,
    SESSION_TOKEN_VALIDITY=5,
    ID_TOKEN_VALIDITY=60
"""
        )
        # ALLOW_UNPROTECTED_ID_TOKEN is going to be deprecated in the future
        # cnx.cursor().execute("alter account testaccount set ALLOW_UNPROTECTED_ID_TOKEN=true;")
        cnx.cursor().execute("alter account testaccount set ALLOW_ID_TOKEN=true;")
        cnx.cursor().execute(
            "alter account testaccount set ID_TOKEN_FEATURE_ENABLED=true;"
        )

    def fin():
        with snowflake.connector.connect(**CONNECTION_PARAMETERS_ADMIN) as cnx:
            cnx.cursor().execute(
                """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=default,
    SESSION_TOKEN_VALIDITY=default,
    ID_TOKEN_VALIDITY=default
"""
            )

    request.addfinalizer(fin)
    return None


@pytest.mark.skipif(
    not (
        CONNECTION_PARAMETERS_SSO
        and CONNECTION_PARAMETERS_ADMIN
        and delete_temporary_credential
    ),
    reason="SSO and ADMIN connection parameters must be provided.",
)
def test_connect_externalbrowser(token_validity_test_values):
    """SSO Id Token Cache tests. This test should only be ran if keyring optional dependency is installed.

    In order to run this test, remove the above pytest.mark.skip annotation and run it. It will popup a windows once
    but the rest connections should not create popups.
    """
    delete_temporary_credential(
        host=CONNECTION_PARAMETERS_SSO["host"],
        user=CONNECTION_PARAMETERS_SSO["user"],
        cred_type=ID_TOKEN,
    )  # delete existing temporary credential
    CONNECTION_PARAMETERS_SSO["client_store_temporary_credential"] = True

    # change database and schema to non-default one
    print(
        "[INFO] 1st connection gets id token and stores in the local cache (keychain/credential manager/cache file). "
        "This popup a browser to SSO login"
    )
    cnx = snowflake.connector.connect(**CONNECTION_PARAMETERS_SSO)
    assert cnx.database == "TESTDB"
    assert cnx.schema == "PUBLIC"
    assert cnx.role == "SYSADMIN"
    assert cnx.warehouse == "REGRESS"
    ret = (
        cnx.cursor()
        .execute(
            "select current_database(), current_schema(), "
            "current_role(), current_warehouse()"
        )
        .fetchall()
    )
    assert ret[0][0] == "TESTDB"
    assert ret[0][1] == "PUBLIC"
    assert ret[0][2] == "SYSADMIN"
    assert ret[0][3] == "REGRESS"
    cnx.close()

    print(
        "[INFO] 2nd connection reads the local cache and uses the id token. "
        "This should not popups a browser."
    )
    CONNECTION_PARAMETERS_SSO["database"] = "testdb"
    CONNECTION_PARAMETERS_SSO["schema"] = "testschema"
    cnx = snowflake.connector.connect(**CONNECTION_PARAMETERS_SSO)
    print(
        "[INFO] Running a 10 seconds query. If the session expires in 10 "
        "seconds, the query should renew the token in the middle, "
        "and the current objects should be refreshed."
    )
    cnx.cursor().execute("select seq8() from table(generator(timelimit=>10))")
    assert cnx.database == "TESTDB"
    assert cnx.schema == "TESTSCHEMA"
    assert cnx.role == "SYSADMIN"
    assert cnx.warehouse == "REGRESS"

    print("[INFO] Running a 1 second query. ")
    cnx.cursor().execute("select seq8() from table(generator(timelimit=>1))")
    assert cnx.database == "TESTDB"
    assert cnx.schema == "TESTSCHEMA"
    assert cnx.role == "SYSADMIN"
    assert cnx.warehouse == "REGRESS"

    print(
        "[INFO] Running a 90 seconds query. This pops up a browser in the "
        "middle of the query."
    )
    cnx.cursor().execute("select seq8() from table(generator(timelimit=>90))")
    assert cnx.database == "TESTDB"
    assert cnx.schema == "TESTSCHEMA"
    assert cnx.role == "SYSADMIN"
    assert cnx.warehouse == "REGRESS"

    cnx.close()

    # change database and schema again to ensure they are overridden
    CONNECTION_PARAMETERS_SSO["database"] = "testdb"
    CONNECTION_PARAMETERS_SSO["schema"] = "testschema"
    cnx = snowflake.connector.connect(**CONNECTION_PARAMETERS_SSO)
    assert cnx.database == "TESTDB"
    assert cnx.schema == "TESTSCHEMA"
    assert cnx.role == "SYSADMIN"
    assert cnx.warehouse == "REGRESS"
    cnx.close()

    with snowflake.connector.connect(**CONNECTION_PARAMETERS_ADMIN) as cnx_admin:
        # cnx_admin.cursor().execute("alter account testaccount set ALLOW_UNPROTECTED_ID_TOKEN=false;")
        cnx_admin.cursor().execute(
            "alter account testaccount set ALLOW_ID_TOKEN=false;"
        )
        cnx_admin.cursor().execute(
            "alter account testaccount set ID_TOKEN_FEATURE_ENABLED=false;"
        )
    print(
        "[INFO] Login again with ALLOW_UNPROTECTED_ID_TOKEN unset. Please make sure this pops up the browser"
    )
    cnx = snowflake.connector.connect(**CONNECTION_PARAMETERS_SSO)
    cnx.close()
