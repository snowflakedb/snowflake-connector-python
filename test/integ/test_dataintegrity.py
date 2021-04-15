#!/usr/bin/env python -O
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

"""Script to test database capabilities and the DB-API interface.

It tests for functionality and data integrity for some of the basic data types. Adapted from a script
taken from the MySQL python driver.
"""

import random
import time
from math import fabs

import pytz

from snowflake.connector.dbapi import DateFromTicks, TimeFromTicks, TimestampFromTicks

from ..randomize import random_string


def table_exists(conn_cnx, name):
    with conn_cnx() as cnx:
        with cnx.cursor() as cursor:
            try:
                cursor.execute("select * from %s where 1=0" % name)
            except Exception:
                cnx.rollback()
                return False
            else:
                return True


def create_table(conn_cnx, columndefs, partial_name):
    table = '"dbabi_dibasic_{}"'.format(partial_name)
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            "CREATE OR REPLACE TABLE {table} ({columns})".format(
                table=table, columns="\n".join(columndefs)
            )
        )
    return table


def check_data_integrity(conn_cnx, columndefs, partial_name, generator):
    rows = random.randrange(10, 15)
    #    floating_point_types = ('REAL','DOUBLE','DECIMAL')
    floating_point_types = ("REAL", "DOUBLE")

    table = create_table(conn_cnx, columndefs, partial_name)
    with conn_cnx() as cnx:
        with cnx.cursor() as cursor:
            # insert some data as specified by generator passed in
            insert_statement = "INSERT INTO {} VALUES ({})".format(
                table,
                ",".join(["%s"] * len(columndefs)),
            )
            data = [
                [generator(i, j) for j in range(len(columndefs))] for i in range(rows)
            ]
            cursor.executemany(insert_statement, data)
            cnx.commit()

            # verify 2 things: correct number of rows, correct values for
            # each row
            cursor.execute("select * from {} order by 1".format(table))
            result_sequences = cursor.fetchall()
            results = []
            for i in result_sequences:
                results.append(i)

            # verify the right number of rows were returned
            assert len(results) == rows, (
                "fetchall did not return " "expected number of rows"
            )

            # verify the right values were returned
            # for numbers, allow a difference of .000001
            for x, y in zip(results, sorted(data)):
                if any(data_type in partial_name for data_type in floating_point_types):
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


def test_INT(conn_cnx):
    # Number data
    def generator(row, col):
        return row * row

    check_data_integrity(conn_cnx, ("col1 INT",), "INT", generator)


def test_DECIMAL(conn_cnx):
    # DECIMAL
    def generator(row, col):
        from decimal import Decimal

        return Decimal("%d.%02d" % (row, col))

    check_data_integrity(conn_cnx, ("col1 DECIMAL(5,2)",), "DECIMAL", generator)


def test_REAL(conn_cnx):
    def generator(row, col):
        return row * 1000.0

    check_data_integrity(conn_cnx, ("col1 REAL",), "REAL", generator)


def test_REAL2(conn_cnx):
    def generator(row, col):
        return row * 3.14

    check_data_integrity(conn_cnx, ("col1 REAL",), "REAL", generator)


def test_DOUBLE(conn_cnx):
    def generator(row, col):
        return row / 1e-99

    check_data_integrity(conn_cnx, ("col1 DOUBLE",), "DOUBLE", generator)


def test_FLOAT(conn_cnx):
    def generator(row, col):
        return row * 2.0

    check_data_integrity(conn_cnx, ("col1 FLOAT(67)",), "FLOAT", generator)


def test_DATE(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        return DateFromTicks(ticks + row * 86400 - col * 1313)

    check_data_integrity(conn_cnx, ("col1 DATE",), "DATE", generator)


def test_STRING(conn_cnx):
    def generator(row, col):
        import string

        rstr = random_string(1024, choices=string.ascii_letters + string.digits)
        return rstr

    check_data_integrity(conn_cnx, ("col2 STRING",), "STRING", generator)


def test_TEXT(conn_cnx):
    def generator(row, col):
        rstr = "".join([chr(i) for i in range(33, 127)] * 100)
        return rstr

    check_data_integrity(conn_cnx, ("col2 TEXT",), "TEXT", generator)


def test_VARCHAR(conn_cnx):
    def generator(row, col):
        import string

        rstr = random_string(50, choices=string.ascii_letters + string.digits)
        return rstr

    check_data_integrity(conn_cnx, ("col2 VARCHAR",), "VARCHAR", generator)


def test_BINARY(conn_cnx):
    def generator(row, col):
        return bytes(random.getrandbits(8) for _ in range(50))

    check_data_integrity(conn_cnx, ("col1 BINARY",), "BINARY", generator)


def test_TIMESTAMPNTZ(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        return TimestampFromTicks(ticks + row * 86400 - col * 1313)

    check_data_integrity(conn_cnx, ("col1 TIMESTAMPNTZ",), "TIMESTAMPNTZ", generator)


def test_TIMESTAMPNTZ_EXPLICIT(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        return TimestampFromTicks(ticks + row * 86400 - col * 1313)

    check_data_integrity(
        conn_cnx,
        ("col1 TIMESTAMP without time zone",),
        "TIMESTAMPNTZ_EXPLICIT",
        generator,
    )


# string that contains control characters (white spaces), etc.
def test_DATETIME(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("US/Pacific")
        ret = myzone.localize(ret)

    check_data_integrity(conn_cnx, ("col1 TIMESTAMP",), "DATETIME", generator)


def test_TIMESTAMP(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("US/Pacific")
        return myzone.localize(ret)

    check_data_integrity(conn_cnx, ("col1 TIMESTAMP_LTZ",), "TIMESTAMP", generator)


def test_TIMESTAMP_EXPLICIT(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("Australia/Sydney")
        return myzone.localize(ret)

    check_data_integrity(
        conn_cnx,
        ("col1 TIMESTAMP with local time zone",),
        "TIMESTAMP_EXPLICIT",
        generator,
    )


def test_TIMESTAMPTZ(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("America/Vancouver")
        return myzone.localize(ret)

    check_data_integrity(conn_cnx, ("col1 TIMESTAMPTZ",), "TIMESTAMPTZ", generator)


def test_TIMESTAMPTZ_EXPLICIT(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("America/Vancouver")
        return myzone.localize(ret)

    check_data_integrity(
        conn_cnx, ("col1 TIMESTAMP with time zone",), "TIMESTAMPTZ_EXPLICIT", generator
    )


def test_TIMESTAMPLTZ(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(ticks + row * 86400 - col * 1313)
        myzone = pytz.timezone("America/New_York")
        return myzone.localize(ret)

    check_data_integrity(conn_cnx, ("col1 TIMESTAMPLTZ",), "TIMESTAMPLTZ", generator)


def test_fractional_TIMESTAMP(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimestampFromTicks(
            ticks + row * 86400 - col * 1313 + row * 0.7 * col / 3.0
        )
        myzone = pytz.timezone("Europe/Paris")
        return myzone.localize(ret)

    check_data_integrity(
        conn_cnx, ("col1 TIMESTAMP_LTZ",), "TIMESTAMP_fractional", generator
    )


def test_TIME(conn_cnx):
    ticks = time.time()

    def generator(row, col):
        ret = TimeFromTicks(ticks + row * 86400 - col * 1313)
        return ret

    check_data_integrity(conn_cnx, ("col1 TIME",), "TIME", generator)
