#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL


@pytest.mark.skipif(
    IS_WINDOWS,
    reason="SnowSQL runs on Python 35+. "
    "Windows doesn't support more than 9999 yeers",
)
def test_snowsql_timestamp_format(conn_cnx):
    """In SnowSQL, OverflowError should not happen."""
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        cnx.cursor().execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cnx.cursor().execute(
            """
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_OUTPUT_FORMAT='DY, DD MON YYYY HH24:MI:SS TZHTZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='DY, DD MON YYYY HH24:MI:SS TZHTZM',
    TIMESTAMP_LTZ_OUTPUT_FORMAT='DY, DD MON YYYY HH24:MI:SS TZHTZM';
"""
        )
        ret = (
            cnx.cursor()
            .execute(
                """
SELECT
    '19999-09-30 12:34:56'::timestamp_ltz,
    '19999-09-30 12:34:56'::timestamp_ntz,
    '2001-09-30 12:34:56.00123400'::timestamp_ntz(8)
"""
            )
            .fetchone()
        )
        assert ret[0] == "Thu, 30 Sep 19999 19:34:56 +0000"
        assert ret[1] == "Thu, 30 Sep 19999 12:34:56 "

        # The last space is included as TZHTZM is an empty value if
        # datatype is datetime.
        assert ret[2] == "Sun, 30 Sep 2001 12:34:56 "

        # NOTE timestamp_tz doesn't accept the timestamp out of range
        # what is the range?


def test_snowsql_timestamp_negative_epoch(conn_cnx):
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        cnx.cursor().execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cnx.cursor().execute(
            """
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIMESTAMP_LTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM';
"""
        )
        ret = (
            cnx.cursor()
            .execute(
                """
    SELECT
        '1969-09-30 12:34:56.123456789'::timestamp_ltz(7),
        '1969-09-30 12:34:56.123456789'::timestamp_ntz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(4),
        '2001-09-30 12:34:56.00123400'::timestamp_ntz(8)
    """
            )
            .fetchone()
        )
        assert ret[0] == "1969-09-30 12:34:56.123456700 -0700"
        assert ret[1] == "1969-09-30 12:34:56.123456780 "
        assert ret[2] == "1969-09-30 12:34:56.123456780 -0800"
        assert ret[3] == "1969-09-30 12:34:56.123400000 -0800"
        # a scale in format forces to add 0 to the end
        assert ret[4] == "2001-09-30 12:34:56.001234000 "
        cnx.cursor().execute(
            """
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM',
    TIMESTAMP_LTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM';
"""
        )
        ret = (
            cnx.cursor()
            .execute(
                """
    SELECT
        '1969-09-30 12:34:56.123456789'::timestamp_ltz(7),
        '1969-09-30 12:34:56.123456789'::timestamp_ntz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(4),
        '2001-09-30 12:34:56.00123400'::timestamp_ntz(8)
    """
            )
            .fetchone()
        )
        assert ret[0] == "1969-09-30 12:34:56.1234567 -0700"
        assert ret[1] == "1969-09-30 12:34:56.12345678 "
        assert ret[2] == "1969-09-30 12:34:56.12345678 -0800"
        assert ret[3] == "1969-09-30 12:34:56.1234 -0800"
        assert ret[4] == "2001-09-30 12:34:56.00123400 "


@pytest.mark.skipolddriver
@pytest.mark.skipif(
    IS_WINDOWS,
    reason="SnowSQL runs on Python 35+. "
    "Windows doesn't support more than 9999 yeers",
)
def test_snowsql_timestamp_ntz(conn_cnx):
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        cnx.cursor().execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )

        prior_to_epoch_list = [
            f"""'1965-09-30 12:34:56.{"".join([str(j) for j in range(1, i + 1)])}'::timestamp_ntz({i})"""
            for i in range(1, 10)
        ]
        after_epoch_list = [
            f"""'2022-02-22 12:34:56.{"".join([str(j) for j in range(1, i + 1)])}'::timestamp_ntz({i})"""
            for i in range(1, 10)
        ]
        float_round_list = [
            f"""'9999-12-31 23:59:59.{"9"*i}'::timestamp_ntz({i})"""
            for i in range(1, 10)
        ]

        select_text = (
            ",\n".join(prior_to_epoch_list)
            + ",\n"
            + ",\n".join(after_epoch_list)
            + ",\n"
            + ",\n".join(float_round_list)
            + ";"
        )

        cnx.cursor().execute(
            """
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM';
"""
        )
        ret = (
            cnx.cursor()
            .execute(
                f"""
    SELECT
        {select_text}
    """
            )
            .fetchone()
        )

        assert (
            len(ret)
            == len(prior_to_epoch_list) + len(after_epoch_list) + len(float_round_list)
            == 27
        )
        for i in range(0, 9):
            assert (
                ret[i]
                == f'1965-09-30 12:34:56.{"".join([str(j) for j in range(1, i + 2)])}{"0"*(9 - i - 1)} '
            )
        for i in range(0, 9):
            assert (
                ret[i + 9]
                == f'2022-02-22 12:34:56.{"".join([str(j) for j in range(1, i + 2)])}{"0"*(9 - i - 1)} '
            )
        for i in range(0, 9):
            assert (
                ret[i + 18] == f'9999-12-31 23:59:59.{"9" * (i + 1)}{"0"*(9 - i - 1)} '
            )

        ret = (
            cnx.cursor()
            .execute(
                """
    SELECT
        '12345-12-31 12:34:56.999649'::timestamp_ntz(6),
        '123-12-31 12:34:56.876321'::timestamp_ntz(6);
    """
            )
            .fetchone()
        )

        assert ret[0] == "12345-12-31 12:34:56.999649000 "
        assert ret[1] == "0123-12-31 12:34:56.876321000 "
