#!/usr/bin/env python -O
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

"""Script to test database capabilities and the DB-API interface.

It tests for functionality and data integrity for some of the basic data types. Adapted from a script
taken from the MySQL python driver.
"""

import random
import string
import time
from decimal import Decimal
from math import fabs

import pytest
import pytz

from snowflake.connector.dbapi import DateFromTicks, TimeFromTicks, TimestampFromTicks

from ..integ_helpers import drop_table
from ..randomize import random_string


def _generate_time(row, col, tz=None, fractional=False):
    res = time.time() + row * 86400 - col * 1313
    if fractional:
        res += row * 0.7 * col / 3.0
    res = TimestampFromTicks(res)
    if tz:
        res = pytz.timezone(tz).localize(res)
    return res


def _create_table(conn_cnx, columndefs, partial_name):
    table = random_string(5, f"check_data_integrity_{partial_name}_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            "CREATE OR REPLACE TABLE {table} ({columns})".format(
                table=table, columns="\n".join(columndefs)
            )
        )
    return table


@pytest.mark.parametrize(
    "columndefs, data_type, generator",
    [
        (("col1 INT",), "INT", lambda i, j: i * i),
        (("col1 DECIMAL(5,2)",), "DECIMAL", lambda i, j: Decimal("%d.%02d" % (i, j))),
        (("col1 REAL",), "REAL", lambda i, j: i * 1000.0),
        (("col1 REAL",), "REAL", lambda i, j: i * 3.14),
        (("col1 DOUBLE",), "DOUBLE", lambda i, j: i / 1e-99),
        (("col1 FLOAT(67)",), "FLOAT", lambda i, j: i * 2.0),
        (
            ("col1 DATE",),
            "DATE",
            lambda i, j: DateFromTicks(time.time() + i * 86400 - j * 1313),
        ),
        (
            ("col2 STRING",),
            "STRING",
            lambda i, j: random_string(
                1024, choices=string.ascii_letters + string.digits
            ),
        ),
        (
            ("col2 TEXT",),
            "TEXT",
            lambda i, j: "".join([chr(i) for i in range(33, 127)] * 100),
        ),
        (
            ("col2 VARCHAR",),
            "VARCHAR",
            lambda i, j: random_string(
                50, choices=string.ascii_letters + string.digits
            ),
        ),
        (
            ("col1 BINARY",),
            "BINARY",
            lambda i, j: bytes(random.getrandbits(8) for _ in range(50)),
        ),
        (("col1 TIMESTAMPNTZ",), "TIMESTAMPNTZ", lambda i, j: _generate_time(i, j)),
        (
            ("col1 TIMESTAMP without time zone",),
            "TIMESTAMPNTZ_EXPLICIT",
            lambda i, j: _generate_time(i, j),
        ),
        (
            ("col1 TIMESTAMP_LTZ",),
            "TIMESTAMP",
            lambda i, j: _generate_time(i, j, "US/Pacific"),
        ),
        (
            ("col1 TIMESTAMP with local time zone",),
            "TIMESTAMP_EXPLICIT",
            lambda i, j: _generate_time(i, j, "Australia/Sydney"),
        ),
        (
            ("col1 TIMESTAMPTZ",),
            "TIMESTAMPTZ",
            lambda i, j: _generate_time(i, j, "America/Vancouver"),
        ),
        (
            ("col1 TIMESTAMP with time zone",),
            "TIMESTAMPTZ_EXPLICIT",
            lambda i, j: _generate_time(i, j, "America/Vancouver"),
        ),
        (
            ("col1 TIMESTAMPLTZ",),
            "TIMESTAMPLTZ",
            lambda i, j: _generate_time(i, j, "America/New_York"),
        ),
        (
            ("col1 TIMESTAMP_LTZ",),
            "TIMESTAMP_fractional",
            lambda i, j: _generate_time(i, j, "Europe/Paris", True),
        ),
        (
            ("col1 TIME",),
            "TIME",
            lambda i, j: TimeFromTicks(time.time() + i * 86400 - j * 1313),
        ),
    ],
)
def test_check_data_integrity(conn_cnx, columndefs, data_type, generator, request):
    rows = random.randrange(10, 15)
    floating_point_types = ("REAL", "DOUBLE")

    table = _create_table(conn_cnx, columndefs, data_type)
    request.addfinalizer(drop_table(conn_cnx, table))

    with conn_cnx() as cnx, cnx.cursor() as cursor:
        # insert some data as specified by generator passed in
        insert_statement = "INSERT INTO {} VALUES ({})".format(
            table,
            ",".join(["%s"] * len(columndefs)),
        )
        data = [[generator(i, j) for j in range(len(columndefs))] for i in range(rows)]
        cursor.executemany(insert_statement, data)
        cnx.commit()

        # verify 2 things: correct number of rows, correct values for
        # each row
        cursor.execute("select * from {} order by 1".format(table))
        results = cursor.fetchall()

        # verify the right number of rows were returned
        assert len(results) == rows, (
            "fetchall did not return " "expected number of rows"
        )

        # verify the right values were returned
        # for numbers, allow a difference of .000001
        for x, y in zip(results, sorted(data)):
            if data_type in floating_point_types:
                for _ in range(rows):
                    df = fabs(float(x[0]) - float(y[0]))
                    if float(y[0]) != 0.0:
                        df = df / float(y[0])
                    assert df <= 0.00000001, (
                        "fetchall did not return correct values within "
                        "the expected range"
                    )
            else:
                assert list(x) == list(y), "fetchall did not return correct values"

        cursor.execute("drop table if exists {}".format(table))
