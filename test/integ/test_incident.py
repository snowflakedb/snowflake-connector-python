#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import warnings
from traceback import format_exc
from uuid import uuid4

import pytest
from mock import patch
from pytest import fail

from snowflake.connector import ProgrammingError, converter
from snowflake.connector.incident import Incident

# NOTE the incident throttling feature is working and will stop returning new
# incident ids, so do not assert them, or don't add many more incidents to be
# reported
from .conftest import RUNNING_AGAINST_LOCAL_SNOWFLAKE


def test_incident_creation():
    error_message = "This is an exception"
    error_stack_trace = "this is\n\twhat happened"
    driver = "unit-testing"
    driver_version = "0.0.0"
    os = "unit testinux"
    os_version = "1.0.0"
    incident = Incident(
        None,
        None,
        driver,
        driver_version,
        error_message,
        error_stack_trace,
        os,
        os_version,
    )
    print(incident)
    assert incident.errorMessage == error_message
    assert incident.errorStackTrace == error_stack_trace
    assert incident.driver == driver
    assert incident.driverVersion == driver_version
    assert incident.os == os
    assert incident.osVersion == os_version


def test_default_values():
    incident = Incident("ji", "ri", "dr", "dv", "em", "est\n\test2")
    print(incident)
    assert incident.jobId == "ji"
    assert incident.requestId == "ri"
    assert incident.driver == "dr"
    assert incident.driverVersion == "dv"
    assert incident.errorMessage == "em"
    assert incident.errorStackTrace == "est\n\test2"
    assert incident.driver
    assert incident.driverVersion
    assert incident.os
    assert incident.osVersion


@pytest.mark.internal
@pytest.mark.skipif(
    not RUNNING_AGAINST_LOCAL_SNOWFLAKE, reason="local Snowflake is necessary"
)
def test_create_incident_from_exception(negative_conn_cnx):
    with negative_conn_cnx() as con:
        try:
            raise ValueError("This is a test")
        except Exception as e:
            em = str(e)
            est = format_exc()
            incident = Incident(None, None, "unit test", "99.99.99", em, est)
            new_incident_id = con.incident.report_incident(incident)
            if new_incident_id is None:
                warnings.warn(
                    UserWarning(
                        "incident reported in 'test_create_incident_from_exception' was ignored"
                    )
                )


@pytest.mark.internal
@pytest.mark.skipif(
    not RUNNING_AGAINST_LOCAL_SNOWFLAKE, reason="local Snowflake is necessary"
)
def test_report_automatic_incident(negative_conn_cnx):
    def helper(number):
        if number == 0:
            raise RuntimeWarning("I'm done")
        else:
            helper(number - 1)

    with negative_conn_cnx() as con:
        try:
            helper(5)
        except RuntimeWarning:
            new_incident_id = con.incident.report_incident(
                job_id=uuid4(), request_id=uuid4()
            )
            if new_incident_id is None:
                warnings.warn(
                    UserWarning(
                        "incident reported in 'test_report_automatic_incident' was ignored"
                    )
                )


@pytest.mark.internal
@pytest.mark.parametrize("app_name", ["asd", "mark"])
@pytest.mark.skipif(
    not RUNNING_AGAINST_LOCAL_SNOWFLAKE, reason="local Snowflake is necessary"
)
def test_reporting_values(app_name, db_parameters):
    import snowflake.connector

    original_paramstyle = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"
    original_blacklist = snowflake.connector.incident.CLS_BLACKLIST
    snowflake.connector.incident.CLS_BLACKLIST = frozenset()
    converter.PYTHON_TO_SNOWFLAKE_TYPE["nonetype"] = None
    db_parameters["internal_application_name"] = app_name
    con = None
    try:
        con = snowflake.connector.connect(**db_parameters)
        con.cursor().execute("alter session set SUPPRESS_INCIDENT_DUMPS=true")
        cursor = con.cursor()
        with patch.object(con.rest, "request") as incident_report:
            cursor.execute("INSERT INTO foo VALUES (?)", [None])
            fail("Shouldn't reach ths statement")
    except ProgrammingError:
        pass  # ignore, should be thrown
    finally:
        converter.PYTHON_TO_SNOWFLAKE_TYPE["nonetype"] = "ANY"
        snowflake.connector.paramstyle = original_paramstyle
        snowflake.connector.incident.CLS_BLACKLIST = original_blacklist
        for tag in incident_report.call_args[0][1]["Tags"]:
            if tag["Name"] == "driver":
                assert tag["Value"] == app_name
        if con is not None:
            con.close()
