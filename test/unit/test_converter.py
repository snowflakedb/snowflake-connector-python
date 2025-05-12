#!/usr/bin/env python
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from logging import getLogger
from uuid import UUID

import numpy
import pytest

from snowflake.connector import ProgrammingError
from snowflake.connector.connection import DefaultConverterClass
from snowflake.connector.converter import SnowflakeConverter
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL

try:
    from src.snowflake.connector.arrow_context import ArrowConverterContext
except ImportError:
    pass

logger = getLogger(__name__)

ConverterSnowSQL = SnowflakeConverterSnowSQL


def test_is_dst():
    """SNOW-6020: Failed to convert to local time during DST is being changed."""
    # DST to non-DST
    convClass = DefaultConverterClass()
    conv = convClass()
    conv.set_parameter("TIMEZONE", "America/Los_Angeles")

    col_meta = {
        "name": "CREATED_ON",
        "type": 6,
        "length": None,
        "precision": None,
        "scale": 3,
        "nullable": True,
    }
    m = conv.to_python_method("TIMESTAMP_LTZ", col_meta)
    ret = m("1414890189.000")

    assert (
        str(ret) == "2014-11-01 18:03:09-07:00"
    ), "Timestamp during from DST to non-DST"

    # non-DST to DST
    col_meta = {
        "name": "CREATED_ON",
        "type": 6,
        "length": None,
        "precision": None,
        "scale": 3,
        "nullable": True,
    }
    m = conv.to_python_method("TIMESTAMP_LTZ", col_meta)
    ret = m("1425780189.000")

    assert (
        str(ret) == "2015-03-07 18:03:09-08:00"
    ), "Timestamp during from non-DST to DST"


def test_more_timestamps():
    conv = ConverterSnowSQL()
    conv.set_parameter("TIMESTAMP_NTZ_OUTPUT_FORMAT", "YYYY-MM-DD HH24:MI:SS.FF9")
    m = conv.to_python_method("TIMESTAMP_NTZ", {"scale": 9})
    assert m("-2208943503.876543211") == "1900-01-01 12:34:56.123456789"
    assert m("-2208943503.000000000") == "1900-01-01 12:34:57.000000000"
    assert m("-2208943503.012000000") == "1900-01-01 12:34:56.988000000"

    conv.set_parameter("TIMESTAMP_NTZ_OUTPUT_FORMAT", "YYYY-MM-DD HH24:MI:SS.FF9")
    m = conv.to_python_method("TIMESTAMP_NTZ", {"scale": 7})
    assert m("-2208943503.8765432") == "1900-01-01 12:34:56.123456800"
    assert m("-2208943503.0000000") == "1900-01-01 12:34:57.000000000"
    assert m("-2208943503.0120000") == "1900-01-01 12:34:56.988000000"


def test_converter_to_snowflake_bytes():
    uuid = UUID("12345678-1234-5678-1234-567812345678")

    converter = SnowflakeConverter()
    assert converter.to_snowflake([uuid.bytes]) == ["X'\x124Vx\x124Vx\x124Vx\x124Vx'"]


def test_converter_to_snowflake_error():
    converter = SnowflakeConverter()
    with pytest.raises(
        ProgrammingError, match=r"Binding data in type \(bogus\) is not supported"
    ):
        converter._bogus_to_snowflake("Bogus")


@pytest.mark.skipolddriver
def test_decfloat_to_decimal_converter():
    ctx = ArrowConverterContext()
    decimal = ctx.DECFLOAT_to_decimal(42, bytes.fromhex("11AA"))
    assert decimal == Decimal("4522e42")


def test_converter_to_snowflake_bindings_error():
    converter = SnowflakeConverter()
    with pytest.raises(
        ProgrammingError,
        match=r"Binding data in type \(somethingsomething\) is not supported",
    ):
        converter._somethingsomething_to_snowflake_bindings("Bogus")


NANOS_PER_DAY = 24 * 60 * 60 * 10**9


@pytest.mark.parametrize("nanos", [0, 1, 999, 1000, 999999, 10**5 * NANOS_PER_DAY - 1])
def test_day_time_interval_int_to_timedelta(nanos):
    converter = ArrowConverterContext()
    assert converter.INTERVAL_DAY_TIME_int_to_timedelta(nanos) == timedelta(
        microseconds=nanos // 1000
    )
    assert converter.INTERVAL_DAY_TIME_int_to_numpy_timedelta(
        nanos
    ) == numpy.timedelta64(nanos, "ns")


@pytest.mark.parametrize("nanos", [0, 1, 999, 1000, 999999, 10**9 * NANOS_PER_DAY - 1])
def test_day_time_interval_decimal_to_timedelta(nanos):
    converter = ArrowConverterContext()
    nano_bytes = nanos.to_bytes(16, byteorder="little", signed=True)
    assert converter.INTERVAL_DAY_TIME_decimal_to_timedelta(nano_bytes) == timedelta(
        microseconds=nanos // 1000
    )
    assert converter.INTERVAL_DAY_TIME_decimal_to_numpy_timedelta(
        nano_bytes
    ) == numpy.timedelta64(nanos // 1_000_000, "ms")


@pytest.mark.parametrize("months", [0, 1, 999, 1000, 999999, 10**9 * 12 - 1])
def test_year_month_interval_to_timedelta(months):
    converter = ArrowConverterContext()
    assert converter.INTERVAL_YEAR_MONTH_to_numpy_timedelta(
        months
    ) == numpy.timedelta64(months, "M")
