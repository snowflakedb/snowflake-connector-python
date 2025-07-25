#!/usr/bin/env python
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import snowflake.connector
from snowflake.connector.converter import ZERO_EPOCH
from snowflake.connector.converter_null import SnowflakeNoConverterToPython

NUMERIC_VALUES = re.compile(r"-?[\d.]*\d$")


def test_converter_no_converter_to_python(db_parameters):
    """Tests no converter.

    This should not translate the Snowflake internal data representation to the Python native types.
    """
    con = snowflake.connector.connect(
        user=db_parameters["user"],
        authenticator=db_parameters["authenticator"],
        private_key_file=db_parameters["private_key_file"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
        converter_class=SnowflakeNoConverterToPython,
    )
    con.cursor().execute(
        """
alter session set python_connector_query_result_format='JSON'
"""
    )

    ret = (
        con.cursor()
        .execute(
            """
select  current_timestamp(),
        1::NUMBER,
        2.0::FLOAT,
        'test1'
"""
        )
        .fetchone()
    )
    assert isinstance(ret[0], str)
    assert NUMERIC_VALUES.match(ret[0])
    assert isinstance(ret[1], str)
    assert NUMERIC_VALUES.match(ret[1])
    con.cursor().execute("create or replace table testtb(c1 timestamp_ntz(6))")
    try:
        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
        # binding value should have no impact
        con.cursor().execute("insert into testtb(c1) values(%s)", (current_time,))
        ret = con.cursor().execute("select * from testtb").fetchone()[0]
        assert ZERO_EPOCH + timedelta(seconds=(float(ret))) == current_time
    finally:
        con.cursor().execute("drop table if exists testtb")
