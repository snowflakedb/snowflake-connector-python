#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import re
from datetime import datetime, timedelta

from snowflake.connector.converter import ZERO_EPOCH
from snowflake.connector.converter_null import SnowflakeNoConverterToPython

from ..integ_helpers import drop_table
from ..randomize import random_string

NUMERIC_VALUES = re.compile(r"-?[\d.]*\d$")


def test_converter_no_converter_to_python(request, conn_cnx):
    """Tests no converter.

    This should not translate the Snowflake internal data representation to the Python native types.
    """
    table_name = random_string(3, prefix="test_converter_no_converter_to_python")
    with conn_cnx(timezone="UTC", converter_class=SnowflakeNoConverterToPython) as con:
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
        con.cursor().execute(f"create table {table_name}(c1 timestamp_ntz(6))")
        request.addfinalizer(drop_table(conn_cnx, table_name))

        current_time = datetime.utcnow()
        # binding value should have no impact
        con.cursor().execute(
            f"insert into {table_name}(c1) values(%s)", (current_time,)
        )
        ret = con.cursor().execute(f"select * from {table_name}").fetchone()[0]
        assert ZERO_EPOCH + timedelta(seconds=(float(ret))) == current_time
