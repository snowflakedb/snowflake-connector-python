#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import itertools
import json
import logging
import os
import random
import re
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta, timezone

import numpy
import pytest

import snowflake.connector
from snowflake.connector.errors import OperationalError, ProgrammingError

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module

try:
    from snowflake.connector.nanoarrow_arrow_iterator import PyArrowIterator  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

try:
    import pandas

    pandas_available = True
except ImportError:
    pandas_available = False


TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

# Basic set of primitive types with synonymous types excluded
PRIMITIVE_DATATYPE_EXAMPLES = {
    "BINARY": [
        None,
        bytearray(b"\xAB"),
        bytearray(b"\xFA\x42\x00"),
    ],
    "BOOLEAN": [None, True, False],
    "CHAR": [None, "a", "b"],
    "DATE": [
        None,
        date(2016, 7, 23),
        date(1970, 1, 1),
        date(1969, 12, 31),
        date(1, 1, 1),
        date(9999, 12, 31),
    ],
    "DOUBLE": [
        -86.6426540296895,
        3.14159265359,
        1.7976931348623157e308,
    ],
    "NUMBER": [None, 1, 2, 3],
    "INTEGER": [
        None,
        0,
        999999999,
        -999999999,
    ],
    "TIME": [
        None,
        time(0, 0, 0),
        time(8, 59, 59),
        time(12, 0, 0),
        time(23, 0, 31),
    ],
    "TIMESTAMP_LTZ": [
        None,
        datetime.strptime("2024-01-01 12:00:00", TIMESTAMP_FMT).replace(
            tzinfo=timezone.utc
        ),
    ],
    "TIMESTAMP_NTZ": [
        None,
        datetime.strptime("2024-01-01 12:00:00", TIMESTAMP_FMT),
    ],
    "TIMESTAMP_TZ": [
        None,
        datetime.strptime("2024-01-01 12:00:00", TIMESTAMP_FMT).replace(
            tzinfo=timezone.utc
        ),
    ],
    "VARCHAR": [None, "ascii_test", b"\xf0\x9f\x98\x80".decode("utf-8")],
    "VARIANT": [None, 1.1, [2.2, 3.3], {"foo": "bar"}],
}

# Some datatypes do not match 1:1 with the original data
PANDAS_REPRS = dict()
PANDAS_STRUCTURED_REPRS = dict()
if pandas_available:
    PANDAS_REPRS = {
        "TIMESTAMP_LTZ": [
            pandas.NaT,
            pandas.Timestamp("2024-01-01 12:00:00+0000", tz="UTC"),
        ],
        "TIMESTAMP_NTZ": [pandas.NaT, pandas.Timestamp("2024-01-01 12:00:00")],
        "TIMESTAMP_TZ": [
            pandas.NaT,
            pandas.Timestamp("2024-01-01 12:00:00+0000", tz="UTC"),
        ],
        "NUMBER": [numpy.NAN, 1.0, 2.0, 3.0],
    }

    PANDAS_STRUCTURED_REPRS = {
        # SNOW-1326075: Timestamp types drop information when converted to pandas
        "TIMESTAMP_LTZ": [None, 1704110400000000000],
        "TIMESTAMP_NTZ": [None, 1704110400000000000],
        "TIMESTAMP_TZ": [None, 1704110400000000000],
    }

ICEBERG_STRUCTURED_REPRS = {
    # SNOW-1320508: Timestamp types have incorrect scale in iceberg tables
    "TIMESTAMP_LTZ": [None, 9223372036854775807],
    "TIMESTAMP_NTZ": [None, 9223372036854775807],
    "TIMESTAMP_TZ": [None, 9223372036854775807],
}


# semi-structured types don't always preserve data through serialization
SEMI_STRUCTURED_REPRS = {
    "BINARY": [None, "ab", "fa4200"],
    "DATE": [
        None,
        "2016-07-23",
        "1970-01-01",
        "1969-12-31",
        "0001-01-01",
        "9999-12-31",
    ],
    "DOUBLE": [-86.6426540296895, 3.14159265359, float("inf")],
    "TIME": [None, "00:00:00", "08:59:59", "12:00:00", "23:00:31"],
    "TIMESTAMP_LTZ": [None, "2024-01-01 12:00:00+00:00"],
    "TIMESTAMP_NTZ": [None, "2024-01-01 12:00:00"],
    "TIMESTAMP_TZ": [None, "2024-01-01 12:00:00+00:00"],
}

ICEBERG_CONFIG = """
CATALOG = 'SNOWFLAKE'
EXTERNAL_VOLUME = 'python_connector_iceberg_exvol'
BASE_LOCATION = 'python_connector_merge_gate';
"""

ICEBERG_UNSUPPORTED_TYPES = {
    "CHAR",
    "NUMBER",
    "TIMESTAMP_TZ",
    "VARIANT",
}


# iceberg testing is only configured in aws at the moment
ICEBERG_ENVIRONMENTS = {"aws"}
STRUCTRED_TYPE_ENVIRONMENTS = {"aws"}
CLOUD = os.getenv("cloud_provider", "dev")
RUNNING_ON_GH = os.getenv("GITHUB_ACTIONS") == "true"

ICEBERG_SUPPORTED = CLOUD in ICEBERG_ENVIRONMENTS and RUNNING_ON_GH or CLOUD == "dev"
STRUCTURED_TYPES_SUPPORTED = (
    CLOUD in STRUCTRED_TYPE_ENVIRONMENTS and RUNNING_ON_GH or CLOUD == "dev"
)

# Generate all valid test cases. By using pytest.param with an id you can
# run a specific test case easier like so:
# pytest 'test/integ/test_arrow_result.py::test_dataypes[BINARY-iceberg-pandas]'
DATATYPE_TEST_CONFIGURATIONS = [
    pytest.param(
        datatype,
        PRIMITIVE_DATATYPE_EXAMPLES[datatype],
        iceberg,
        pandas,
        id=f"{datatype}{'-iceberg' if iceberg else ''}{'-pandas' if pandas else ''}",
    )
    for iceberg, pandas, datatype in itertools.product(
        [True, False],
        [True, False] if pandas_available else [False],
        PRIMITIVE_DATATYPE_EXAMPLES,
    )
    # Run all tests when not converting to pandas or using iceberg
    if iceberg is False
    # Only run iceberg tests on applicable types
    or (ICEBERG_SUPPORTED and iceberg and datatype not in ICEBERG_UNSUPPORTED_TYPES)
]


@contextmanager
def structured_type_wrapped_conn(conn_cnx):
    parameters = {"python_connector_query_result_format": "json"}
    if STRUCTURED_TYPES_SUPPORTED:
        parameters = {
            "python_connector_query_result_format": "arrow",
            "ENABLE_STRUCTURED_TYPES_IN_CLIENT_RESPONSE": True,
            "ENABLE_STRUCTURED_TYPES_NATIVE_ARROW_FORMAT": True,
            "FORCE_ENABLE_STRUCTURED_TYPES_NATIVE_ARROW_FORMAT": True,
            "IGNORE_CLIENT_VESRION_IN_STRUCTURED_TYPES_RESPONSE": True,
        }

    with conn_cnx(session_parameters=parameters) as conn:
        yield conn


def serialize(value):
    if isinstance(value, bytearray):
        return value.hex()
    elif isinstance(value, (date, time)):
        return str(value)
    return value


def dumps(data):
    return json.dumps(data, default=serialize, indent=2)


def verify_datatypes(
    conn_cnx, query, examples, schema, iceberg=False, pandas=False, deserialize=False
):
    table_name = f"arrow_datatype_test_verifaction_table_{random_string(5)}"
    with structured_type_wrapped_conn(conn_cnx) as conn:
        try:
            conn.cursor().execute("alter session set use_cached_result=false")
            iceberg_table, iceberg_config = (
                ("iceberg", ICEBERG_CONFIG) if iceberg else ("", "")
            )
            conn.cursor().execute(
                f"create {iceberg_table} table if not exists {table_name} {schema} {iceberg_config}"
            )
            conn.cursor().execute(f"insert into {table_name} {query}")
            cur = conn.cursor().execute(f"select * from {table_name}")
            if pandas:
                pandas_verify(cur, examples, deserialize)
            else:
                datatype_verify(cur, examples, deserialize)
        finally:
            conn.cursor().execute(f"drop table if exists {table_name}")


def datatype_verify(cur, data, deserialize):
    rows = cur.fetchall()
    assert len(rows) == len(data), "Result should have same number of rows as examples"
    for row, datum in zip(rows, data):
        actual = json.loads(row[0]) if deserialize else row[0]
        assert len(row) == 1, "Result should only have one column."
        assert actual == datum, "Result values should match input examples."


def pandas_verify(cur, data, deserialize):
    pdf = cur.fetch_pandas_all()
    assert len(pdf) == len(data), "Result should have same number of rows as examples"
    for value, datum in zip(pdf.COL.to_list(), data):
        if deserialize:
            value = json.loads(value)
        if isinstance(value, numpy.ndarray):
            value = value.tolist()

        # Numpy nans have to be checked with isnan. nan != nan according to numpy
        if isinstance(value, float) and numpy.isnan(value):
            assert datum is None or numpy.isnan(datum), "nan values should return nan."
        else:
            if isinstance(value, dict):
                value = {
                    k: v.tolist() if isinstance(v, numpy.ndarray) else v
                    for k, v in value.items()
                }
            assert (
                value == datum or value is datum
            ), f"Result value {value} should match input example {datum}."


@pytest.mark.skipif(
    not ICEBERG_SUPPORTED, reason="Iceberg not supported in this envrionment."
)
@pytest.mark.parametrize("datatype", ICEBERG_UNSUPPORTED_TYPES)
def test_iceberg_negative(datatype, conn_cnx):
    table_name = f"arrow_datatype_test_verifaction_table_{random_string(5)}"
    with structured_type_wrapped_conn(conn_cnx) as conn:
        try:
            with pytest.raises(ProgrammingError):
                conn.cursor().execute(
                    f"create iceberg table if not exists {table_name} (col {datatype}) {ICEBERG_CONFIG}"
                )
        finally:
            conn.cursor().execute(f"drop table if exists {table_name}")


@pytest.mark.parametrize(
    "datatype,examples,iceberg,pandas", DATATYPE_TEST_CONFIGURATIONS
)
def test_datatypes(datatype, examples, iceberg, pandas, conn_cnx):
    json_values = re.escape(json.dumps(examples, default=serialize))
    query = f"""
    SELECT
      value :: {datatype} as col
    FROM
      TABLE(FLATTEN(input => parse_json('{json_values}')));
    """
    if pandas:
        examples = PANDAS_REPRS.get(datatype, examples)
    if datatype == "VARIANT":
        examples = [dumps(ex) for ex in examples]
    verify_datatypes(conn_cnx, query, examples, f"(col {datatype})", iceberg, pandas)


@pytest.mark.parametrize(
    "datatype,examples,iceberg,pandas", DATATYPE_TEST_CONFIGURATIONS
)
def test_array(datatype, examples, iceberg, pandas, conn_cnx):
    json_values = re.escape(json.dumps(examples, default=serialize))

    if STRUCTURED_TYPES_SUPPORTED:
        col_type = f"array({datatype})"
        if datatype == "VARIANT":
            examples = [dumps(ex) if ex else ex for ex in examples]
        elif pandas:
            if iceberg:
                examples = ICEBERG_STRUCTURED_REPRS.get(datatype, examples)
            else:
                examples = PANDAS_STRUCTURED_REPRS.get(datatype, examples)
    else:
        col_type = "array"
        examples = SEMI_STRUCTURED_REPRS.get(datatype, examples)

    query = f"""
    SELECT
      parse_json('{json_values}') :: {col_type} as col
    """
    verify_datatypes(
        conn_cnx,
        query,
        (examples,),
        f"(col {col_type})",
        iceberg,
        pandas,
        not STRUCTURED_TYPES_SUPPORTED,
    )


@pytest.mark.skipif(
    not STRUCTURED_TYPES_SUPPORTED, reason="Testing structured type feature."
)
def test_structured_type_binds(conn_cnx):
    original_style = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"
    data = (
        1,
        [True, False, True],
        {"k1": 1, "k2": 2, "k3": 3, "k4": 4, "k5": 5},
        {"city": "san jose", "population": 0.05},
        [1.0, 3.1, 4.5],
    )
    json_data = [json.dumps(d) for d in data]
    schema = "(num number, arr_b array(boolean), map map(varchar, int), obj object(city varchar, population float), arr_f array(float))"
    table_name = f"arrow_structured_type_binds_test_{random_string(5)}"
    with structured_type_wrapped_conn(conn_cnx) as conn:
        try:
            conn.cursor().execute("alter session set enable_bind_stage_v2=Enable")
            conn.cursor().execute(f"create table if not exists {table_name} {schema}")
            conn.cursor().execute(
                f"insert into {table_name} select ?, ?, ?, ?, ?", json_data
            )
            result = conn.cursor().execute(f"select * from {table_name}").fetchall()
            assert result[0] == data

            # Binds don't work with values statement yet
            with pytest.raises(ProgrammingError):
                conn.cursor().execute(
                    f"insert into {table_name} values (?, ?, ?, ?, ?)", json_data
                )
        finally:
            snowflake.connector.paramstyle = original_style
            conn.cursor().execute(f"drop table if exists {table_name}")


@pytest.mark.skipif(
    not STRUCTURED_TYPES_SUPPORTED, reason="map type not supported in this environment"
)
@pytest.mark.parametrize("key_type", ["varchar", "number"])
@pytest.mark.parametrize(
    "datatype,examples,iceberg,pandas", DATATYPE_TEST_CONFIGURATIONS
)
def test_map(key_type, datatype, examples, iceberg, pandas, conn_cnx):
    if iceberg and key_type == "number":
        pytest.skip("Iceberg does not support number keys.")
    data = {str(i) if key_type == "varchar" else i: ex for i, ex in enumerate(examples)}
    json_string = re.escape(json.dumps(data, default=serialize))

    if datatype == "VARIANT":
        data = {k: dumps(v) if v else v for k, v in data.items()}
        if pandas:
            data = list(data.items())
    elif pandas:
        examples = PANDAS_STRUCTURED_REPRS.get(datatype, examples)
        data = [
            (str(i) if key_type == "varchar" else i, ex)
            for i, ex in enumerate(examples)
        ]

    query = f"""
    SELECT
      parse_json('{json_string}') :: map({key_type}, {datatype}) as col
    """

    if iceberg and pandas and datatype in ICEBERG_STRUCTURED_REPRS:
        with pytest.raises(ValueError):
            # SNOW-1320508: Timestamp types nested in maps currently cause an exception for iceberg tables
            verify_datatypes(
                conn_cnx,
                query,
                [data],
                f"(col map({key_type}, {datatype}))",
                iceberg,
                pandas,
            )
    else:
        verify_datatypes(
            conn_cnx,
            query,
            [data],
            f"(col map({key_type}, {datatype}))",
            iceberg,
            pandas,
        )


@pytest.mark.parametrize(
    "datatype,examples,iceberg,pandas", DATATYPE_TEST_CONFIGURATIONS
)
def test_object(datatype, examples, iceberg, pandas, conn_cnx):
    fields = [f"{datatype}_{i}" for i in range(len(examples))]
    data = {k: v for k, v in zip(fields, examples)}
    json_string = re.escape(json.dumps(data, default=serialize))

    if STRUCTURED_TYPES_SUPPORTED:
        schema = ", ".join(f"{field} {datatype}" for field in fields)
        col_type = f"object({schema})"
        if datatype == "VARIANT":
            examples = [dumps(s) if s else s for s in examples]
        elif pandas:
            if iceberg:
                examples = ICEBERG_STRUCTURED_REPRS.get(datatype, examples)
            else:
                examples = PANDAS_STRUCTURED_REPRS.get(datatype, examples)
    else:
        col_type = "object"
        examples = SEMI_STRUCTURED_REPRS.get(datatype, examples)
    expected_data = {k: v for k, v in zip(fields, examples)}

    query = f"""
    SELECT
      parse_json('{json_string}') :: {col_type} as col
    """

    if iceberg and pandas and datatype in ICEBERG_STRUCTURED_REPRS:
        with pytest.raises(ValueError):
            # SNOW-1320508: Timestamp types nested in objects currently cause an exception for iceberg tables
            verify_datatypes(
                conn_cnx, query, [expected_data], f"(col {col_type})", iceberg, pandas
            )
    else:
        verify_datatypes(
            conn_cnx,
            query,
            [expected_data],
            f"(col {col_type})",
            iceberg,
            pandas,
            not STRUCTURED_TYPES_SUPPORTED,
        )


@pytest.mark.skipif(
    not STRUCTURED_TYPES_SUPPORTED, reason="map type not supported in this environment"
)
@pytest.mark.parametrize("pandas", [True, False] if pandas_available else [False])
@pytest.mark.parametrize("iceberg", [True, False])
def test_nested_types(conn_cnx, iceberg, pandas):
    data = {"child": [{"key1": {"struct_field": "value"}}]}
    json_string = re.escape(json.dumps(data, default=serialize))
    query = f"""
    SELECT
      parse_json('{json_string}') :: object(child array(map (varchar, object(struct_field varchar)))) as col
    """
    if pandas:
        data = {
            "child": [
                [
                    ("key1", {"struct_field": "value"}),
                ]
            ]
        }
    verify_datatypes(
        conn_cnx,
        query,
        [data],
        "(col object(child array(map (varchar, object(struct_field varchar)))))",
        iceberg,
        pandas,
    )


def test_select_tinyint(conn_cnx):
    cases = [0, 1, -1, 127, -128]
    table = "test_arrow_tiny_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_tinyint(conn_cnx):
    cases = [0.0, 0.11, -0.11, 1.27, -1.28]
    table = "test_arrow_tiny_int"
    column = "(a number(5,3))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_smallint(conn_cnx):
    cases = [0, 1, -1, 127, -128, 128, -129, 32767, -32768]
    table = "test_arrow_small_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_smallint(conn_cnx):
    cases = ["0", "2.0", "-2.0", "32.767", "-32.768"]
    table = "test_arrow_small_int"
    column = "(a number(5,3))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_int(conn_cnx):
    cases = [
        0,
        1,
        -1,
        127,
        -128,
        128,
        -129,
        32767,
        -32768,
        32768,
        -32769,
        2147483647,
        -2147483648,
    ]
    table = "test_arrow_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_int(conn_cnx):
    cases = ["0", "0.123456789", "-0.123456789", "0.2147483647", "-0.2147483647"]
    table = "test_arrow_int"
    column = "(a number(10,9))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_bigint(conn_cnx):
    cases = [
        0,
        1,
        -1,
        127,
        -128,
        128,
        -129,
        32767,
        -32768,
        32768,
        -32769,
        2147483647,
        -2147483648,
        2147483648,
        -2147483649,
        9223372036854775807,
        -9223372036854775808,
    ]
    table = "test_arrow_bigint"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_bigint(conn_cnx):
    cases = [
        "0",
        "0.000000000000000001",
        "-0.000000000000000001",
        "0.000000000000000127",
        "-0.000000000000000128",
        "0.000000000000000128",
        "-0.000000000000000129",
        "0.000000000000032767",
        "-0.000000000000032768",
        "0.000000000000032768",
        "-0.000000000000032769",
        "0.000000002147483647",
        "-0.000000002147483648",
        "0.000000002147483648",
        "-0.000000002147483649",
        "9.223372036854775807",
        "-9.223372036854775808",
    ]
    table = "test_arrow_bigint"
    column = "(a number(38,18))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_decimal(conn_cnx):
    cases = [
        "10000000000000000000000000000000000000",
        "12345678901234567890123456789012345678",
        "99999999999999999999999999999999999999",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,0))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_decimal(conn_cnx):
    cases = [
        "0",
        "0.000000000000000001",
        "-0.000000000000000001",
        "0.000000000000000127",
        "-0.000000000000000128",
        "0.000000000000000128",
        "-0.000000000000000129",
        "0.000000000000032767",
        "-0.000000000000032768",
        "0.000000000000032768",
        "-0.000000000000032769",
        "0.000000002147483647",
        "-0.000000002147483648",
        "0.000000002147483648",
        "-0.000000002147483649",
        "9.223372036854775807",
        "-9.223372036854775808",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_large_scaled_decimal(conn_cnx):
    cases = [
        "1.0000000000000000000000000000000000000",
        "1.2345678901234567890123456789012345678",
        "9.9999999999999999999999999999999999999",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_scaled_decimal_SNOW_133561(conn_cnx):
    cases = [
        "0",
        "1.2345",
        "2.3456",
        "-9.999",
        "-1.000",
        "-3.4567",
        "3.4567",
        "4.5678",
        "5.6789",
        "NULL",
    ]
    table = "test_scaled_decimal_SNOW_133561"
    column = "(a number(38,10))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_boolean(conn_cnx):
    cases = ["true", "false", "true"]
    table = "test_arrow_boolean"
    column = "(a boolean)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("boolean", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext, reason="arrow_iterator extension is not built."
)
def test_select_double_precision(conn_cnx):
    cases = [
        # SNOW-31249
        "-86.6426540296895",
        "3.14159265359",
        # SNOW-76269
        "1.7976931348623157e+308",
        "1.7e+308",
        "1.7976931348623151e+308",
        "-1.7976931348623151e+308",
        "-1.7e+308",
        "-1.7976931348623157e+308",
    ]
    table = "test_arrow_double"
    column = "(a double)"
    values = "(" + "),(".join([f"{i}, {c}" for i, c in enumerate(cases)]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases)
    col_count = 1
    iterate_over_test_chunk(
        "float", conn_cnx, sql_text, row_count, col_count, expected=cases
    )
    finish(conn_cnx, table)


def test_select_semi_structure(conn_cnx):
    sql_text = """select array_construct(10, 20, 30),
        array_construct(null, 'hello', 3::double, 4, 5),
        array_construct(),
        object_construct('a',1,'b','BBBB', 'c',null),
        object_construct('Key_One', parse_json('NULL'), 'Key_Two', null, 'Key_Three', 'null'),
        to_variant(3.2),
        parse_json('{ "a": null}'),
        100::variant;
    """
    row_count = 1
    col_count = 8
    iterate_over_test_chunk("struct", conn_cnx, sql_text, row_count, col_count)


def test_select_vector(conn_cnx, is_public_test):
    if is_public_test:
        pytest.xfail(
            reason="This feature hasn't been rolled out for public Snowflake deployments yet."
        )

    sql_text = """select [1,2,3]::vector(int,3),
        [1.1,2.2]::vector(float,2),
        NULL::vector(int,2),
        NULL::vector(float,3);
    """
    row_count = 1
    col_count = 4
    iterate_over_test_chunk("vector", conn_cnx, sql_text, row_count, col_count)


def test_select_time(conn_cnx):
    for scale in range(10):
        select_time_with_scale(conn_cnx, scale)


def select_time_with_scale(conn_cnx, scale):
    cases = [
        "00:01:23",
        "00:01:23.1",
        "00:01:23.12",
        "00:01:23.123",
        "00:01:23.1234",
        "00:01:23.12345",
        "00:01:23.123456",
        "00:01:23.1234567",
        "00:01:23.12345678",
        "00:01:23.123456789",
    ]
    table = "test_arrow_time"
    column = f"(a time({scale}))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, '{c}'" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("time", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_date(conn_cnx):
    cases = [
        "2016-07-23",
        "1970-01-01",
        "1969-12-31",
        "0001-01-01",
        "9999-12-31",
    ]
    table = "test_arrow_time"
    column = "(a date)"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, '{c}'" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("date", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


@pytest.mark.parametrize("scale", range(10))
@pytest.mark.parametrize("type", ["timestampntz", "timestampltz", "timestamptz"])
def test_select_timestamp_with_scale(conn_cnx, scale, type):
    cases = [
        "2017-01-01 12:00:00",
        "2014-01-02 16:00:00",
        "2014-01-02 12:34:56",
        "2017-01-01 12:00:00.123456789",
        "2014-01-02 16:00:00.000000001",
        "2014-01-02 12:34:56.1",
        "1969-12-31 23:59:59.000000001",
        "1969-12-31 23:59:58.000000001",
        "1969-11-30 23:58:58.000001001",
        "1970-01-01 00:00:00.123412423",
        "1970-01-01 00:00:01.000001",
        "1969-12-31 11:59:59.001",
        "0001-12-31 11:59:59.11",
    ]
    table = "test_arrow_timestamp"
    column = f"(a {type}({scale}))"
    values = (
        "(-1, NULL), ("
        + "),(".join([f"{i}, '{c}'" for i, c in enumerate(cases)])
        + f"), ({len(cases)}, NULL)"
    )
    init(conn_cnx, table, column, values)
    sql_text = f"select a from {table} order by s"
    row_count = len(cases) + 2
    col_count = 1
    # TODO SNOW-534252
    iterate_over_test_chunk(
        type, conn_cnx, sql_text, row_count, col_count, eps=timedelta(microseconds=1)
    )
    finish(conn_cnx, table)


def test_select_with_string(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    length = random.randint(1, 10)
    sql_text = (
        "select seq4() as c1, randstr({}, random({})) as c2 from ".format(
            length, random_seed
        )
        + "table(generator(rowcount=>50000)) order by c1"
    )
    iterate_over_test_chunk("string", conn_cnx, sql_text, row_count, col_count)


def test_select_with_bool(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    sql_text = (
        "select seq4() as c1, as_boolean(uniform(0, 1, random({}))) as c2 from ".format(
            random_seed
        )
        + f"table(generator(rowcount=>{row_count})) order by c1"
    )
    iterate_over_test_chunk("bool", conn_cnx, sql_text, row_count, col_count)


def test_select_with_float(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    pow_val = random.randint(0, 10)
    val_len = random.randint(0, 16)
    # if we assign val_len a larger value like 20, then the precision difference between c++ and python will become
    # very obvious so if we meet some error in this test in the future, please check that whether it is caused by
    # different precision between python and c++
    val_range = random.randint(0, 10**val_len)

    sql_text = "select seq4() as c1, as_double(uniform({}, {}, random({})))/{} as c2 from ".format(
        -val_range, val_range, random_seed, 10**pow_val
    ) + "table(generator(rowcount=>{})) order by c1".format(
        row_count
    )
    iterate_over_test_chunk(
        "float", conn_cnx, sql_text, row_count, col_count, eps=10 ** (-pow_val + 1)
    )


def test_select_with_empty_resultset(conn_cnx):
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute("alter session set query_result_format='ARROW_FORCE'")
        cursor.execute(
            "alter session set python_connector_query_result_format='ARROW_FORCE'"
        )
        cursor.execute("select seq4() from table(generator(rowcount=>100)) limit 0")

        assert cursor.fetchone() is None


def test_select_with_large_resultset(conn_cnx):
    col_count = 5
    row_count = 1000000
    random_seed = get_random_seed()

    sql_text = (
        "select seq4() as c1, "
        "uniform(-10000, 10000, random({})) as c2, "
        "randstr(5, random({})) as c3, "
        "randstr(10, random({})) as c4, "
        "uniform(-100000, 100000, random({})) as c5 "
        "from table(generator(rowcount=>{}))".format(
            random_seed, random_seed, random_seed, random_seed, row_count
        )
    )

    iterate_over_test_chunk("large_resultset", conn_cnx, sql_text, row_count, col_count)


def test_dict_cursor(conn_cnx):
    with conn_cnx() as cnx:
        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute("alter session set python_connector_query_result_format='ARROW'")

            # first test small result generated by GS
            ret = c.execute("select 1 as foo, 2 as bar").fetchone()
            assert ret["FOO"] == 1
            assert ret["BAR"] == 2

            # test larger result set
            row_index = 1
            for row in c.execute(
                "select row_number() over (order by val asc) as foo, "
                "row_number() over (order by val asc) as bar "
                "from (select seq4() as val from table(generator(rowcount=>10000)));"
            ):
                assert row["FOO"] == row_index
                assert row["BAR"] == row_index
                row_index += 1


def test_fetch_as_numpy_val(conn_cnx):
    with conn_cnx(numpy=True) as cnx:
        cursor = cnx.cursor()
        cursor.execute("alter session set python_connector_query_result_format='ARROW'")

        val = cursor.execute(
            """
select 1.23456::double, 1.3456::number(10, 4), 1234567::number(10, 0)
"""
        ).fetchone()
        assert isinstance(val[0], numpy.float64)
        assert val[0] == numpy.float64("1.23456")
        assert isinstance(val[1], numpy.float64)
        assert val[1] == numpy.float64("1.3456")
        assert isinstance(val[2], numpy.int64)
        assert val[2] == numpy.float64("1234567")

        val = cursor.execute(
            """
select '2019-08-10'::date, '2019-01-02 12:34:56.1234'::timestamp_ntz(4),
'2019-01-02 12:34:56.123456789'::timestamp_ntz(9), '2019-01-02 12:34:56.123456789'::timestamp_ntz(8)
"""
        ).fetchone()
        assert isinstance(val[0], numpy.datetime64)
        assert val[0] == numpy.datetime64("2019-08-10")
        assert isinstance(val[1], numpy.datetime64)
        assert val[1] == numpy.datetime64("2019-01-02 12:34:56.1234")
        assert isinstance(val[2], numpy.datetime64)
        assert val[2] == numpy.datetime64("2019-01-02 12:34:56.123456789")
        assert isinstance(val[3], numpy.datetime64)
        assert val[3] == numpy.datetime64("2019-01-02 12:34:56.12345678")


def get_random_seed():
    random.seed(datetime.now().timestamp())
    return random.randint(0, 10000)


def iterate_over_test_chunk(
    test_name, conn_cnx, sql_text, row_count, col_count, eps=None, expected=None
):
    with conn_cnx() as json_cnx:
        with conn_cnx() as arrow_cnx:
            if expected is None:
                cursor_json = json_cnx.cursor()
                cursor_json.execute("alter session set query_result_format='JSON'")
                cursor_json.execute(
                    "alter session set python_connector_query_result_format='JSON'"
                )
                cursor_json.execute(sql_text)

            cursor_arrow = arrow_cnx.cursor()
            cursor_arrow.execute("alter session set use_cached_result=false")
            cursor_arrow.execute("alter session set query_result_format='ARROW_FORCE'")
            cursor_arrow.execute(
                "alter session set python_connector_query_result_format='ARROW_FORCE'"
            )
            cursor_arrow.execute(sql_text)
            assert cursor_arrow._query_result_format == "arrow"

            if expected is None:
                for _ in range(0, row_count):
                    json_res = cursor_json.fetchone()
                    arrow_res = cursor_arrow.fetchone()
                    for j in range(0, col_count):
                        if test_name == "float" and eps is not None:
                            assert abs(json_res[j] - arrow_res[j]) <= eps
                        elif (
                            test_name == "timestampltz"
                            and json_res[j] is not None
                            and eps is not None
                        ):
                            assert abs(json_res[j] - arrow_res[j]) <= eps
                        elif test_name == "vector":
                            assert json_res[j] == pytest.approx(arrow_res[j])
                        else:
                            assert json_res[j] == arrow_res[j]
            else:
                # only support single column for now
                for i in range(0, row_count):
                    arrow_res = cursor_arrow.fetchone()
                    assert str(arrow_res[0]) == expected[i]


@pytest.mark.parametrize("debug_arrow_chunk", [True, False])
def test_arrow_bad_data(conn_cnx, caplog, debug_arrow_chunk):
    with caplog.at_level(logging.DEBUG):
        with conn_cnx(
            debug_arrow_chunk=debug_arrow_chunk
        ) as arrow_cnx, arrow_cnx.cursor() as cursor:
            cursor.execute("select 1")
            cursor._result_set.batches[0]._data = base64.b64encode(b"wrong_data")
            with pytest.raises(OperationalError):
                cursor.fetchone()
    expr = bool("arrow data can not be parsed" in caplog.text)
    assert expr if debug_arrow_chunk else not expr


def init(conn_cnx, table, column, values):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        column_with_seq = column[0] + "s number, " + column[1:]
        cursor_json.execute(f"create or replace table {table} {column_with_seq}")
        cursor_json.execute(f"insert into {table} values {values}")


def finish(conn_cnx, table):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        cursor_json.execute(f"drop table IF EXISTS {table};")
