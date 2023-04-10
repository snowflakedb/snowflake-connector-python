#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import time
from datetime import date, datetime, timedelta
from logging import getLogger
from time import struct_time
from typing import Any, Callable

import pytz

from .compat import IS_WINDOWS
from .constants import is_date_type_name, is_timestamp_type_name
from .converter import (
    ZERO_EPOCH,
    SnowflakeConverter,
    _adjust_fraction_of_nanoseconds,
    _extract_timestamp,
    _generate_tzinfo_from_tzoffset,
)
from .sfbinaryformat import SnowflakeBinaryFormat, binary_to_python
from .sfdatetime import SnowflakeDateFormat, SnowflakeDateTime, SnowflakeDateTimeFormat

MICROSECONDS_ZERO_FILL = "000000"
logger = getLogger(__name__)


def format_sftimestamp(
    ctx: dict[str, Any], value: datetime | struct_time, franction_of_nanoseconds: int
) -> str:
    sf_datetime = SnowflakeDateTime(
        datetime=value, nanosecond=franction_of_nanoseconds, scale=ctx.get("scale")
    )
    return ctx["fmt"].format(sf_datetime) if ctx.get("fmt") else str(sf_datetime)


def _extract_timestamp_snowsql(value: str, ctx: dict) -> tuple[int, int, int]:
    scale = ctx["scale"]
    sign = 1 if value[0] != "-" else -1
    value_without_sign = value[1:] if value[0] == "-" else value

    # we can not simply use float(value) to convert string to float
    # because python float will lost precision, it will round up in case when decimal part of just all 9s
    # e.g. 253402300799.999999 will just be 253402300800.0 which will further generate incorrect datetime
    # related issue: SNOW-730092
    components = value_without_sign.split(".")
    fraction_of_seconds = int(components[0])
    fraction_of_microseconds = 0
    if len(components) == 2:
        # timestamp with decimal
        fraction_of_microseconds = (
            float(components[1][0:6])
            if scale > 6
            else int(components[1][:scale] + MICROSECONDS_ZERO_FILL[: 6 - scale])
        )

    fraction_of_nanoseconds = _adjust_fraction_of_nanoseconds(
        value, ctx["max_fraction"], scale
    )
    return (
        sign * fraction_of_seconds,
        sign * fraction_of_microseconds,
        fraction_of_nanoseconds,
    )


class SnowflakeConverterSnowSQL(SnowflakeConverter):
    """Snowflake Converter for SnowSQL.

    Format data instead of just converting the values into native
    Python objects.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._support_negative_year = kwargs.get("support_negative_year", True)

    def _get_format(self, type_name: str) -> str:
        """Gets the format."""
        fmt = None
        if type_name == "DATE":
            fmt = self._parameters.get("DATE_OUTPUT_FORMAT")
            if not fmt:
                fmt = "YYYY-MM-DD"
        elif type_name == "TIME":
            fmt = self._parameters.get("TIME_OUTPUT_FORMAT")
        elif type_name + "_OUTPUT_FORMAT" in self._parameters:
            fmt = self._parameters[type_name + "_OUTPUT_FORMAT"]
            if not fmt:
                fmt = self._parameters["TIMESTAMP_OUTPUT_FORMAT"]
        elif type_name == "BINARY":
            fmt = self._parameters.get("BINARY_OUTPUT_FORMAT")
        return fmt

    #
    # FROM Snowflake to Python objects
    #
    # Note: Callable doesn't implement operator|
    def to_python_method(
        self, type_name: str, column: dict[str, Any]
    ) -> Callable | None:
        ctx = column.copy()
        if ctx.get("scale") is not None:
            ctx["max_fraction"] = int(10 ** ctx["scale"])
            ctx["zero_fill"] = "0" * (9 - ctx["scale"])
        fmt = None
        if is_date_type_name(type_name):
            datetime_class = time.struct_time if not IS_WINDOWS else date
            fmt = SnowflakeDateFormat(
                self._get_format(type_name),
                support_negative_year=self._support_negative_year,
                datetime_class=datetime_class,
            )
        elif is_timestamp_type_name(type_name):
            fmt = SnowflakeDateTimeFormat(
                self._get_format(type_name),
                data_type=type_name,
                support_negative_year=self._support_negative_year,
                datetime_class=SnowflakeDateTime,
            )
        elif type_name == "BINARY":
            fmt = SnowflakeBinaryFormat(self._get_format(type_name))
        logger.debug("Type: %s, Format: %s", type_name, fmt)
        ctx["fmt"] = fmt
        converters = [f"_{type_name}_to_python"]
        for conv in converters:
            try:
                return getattr(self, conv)(ctx)
            except AttributeError:
                pass
        logger.warning("No column converter found for type: %s", type_name)
        return None  # Skip conversion

    def _BOOLEAN_to_python(self, ctx):
        """No conversion for SnowSQL."""
        return lambda value: "True" if value in ("1", "True") else "False"

    def _FIXED_to_python(self, ctx):
        """No conversion for SnowSQL."""
        return None

    def _REAL_to_python(self, ctx):
        """No conversion for SnowSQL."""
        return None

    def _BINARY_to_python(self, ctx):
        """BINARY to a string formatted by BINARY_OUTPUT_FORMAT."""
        return lambda value: ctx["fmt"].format(binary_to_python(value))

    def _DATE_to_python(self, ctx: dict[str, str | None]) -> Callable:
        """Converts DATE to struct_time/date.

        No timezone is attached.
        """

        def conv(value: str) -> str:
            return ctx["fmt"].format(time.gmtime(int(value) * (24 * 60 * 60)))

        def conv_windows(value):
            ts = ZERO_EPOCH + timedelta(seconds=int(value) * (24 * 60 * 60))
            return ctx["fmt"].format(date(ts.year, ts.month, ts.day))

        return conv if not IS_WINDOWS else conv_windows

    def _TIMESTAMP_TZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        """Converts TIMESTAMP TZ to datetime.

        The timezone offset is piggybacked.
        """
        scale = ctx["scale"]
        max_fraction = ctx.get("max_fraction")

        def conv0(encoded_value: str) -> str:
            value, tz = encoded_value.split()
            microseconds = float(value)
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            try:
                t = datetime.fromtimestamp(microseconds, tz=tzinfo)
            except OSError as e:
                logger.debug("OSError occurred but falling back to datetime: %s", e)
                t = ZERO_EPOCH + timedelta(seconds=microseconds)
                if pytz.utc != tzinfo:
                    t += tzinfo.utcoffset(t)
                t = t.replace(tzinfo=tzinfo)
            fraction_of_nanoseconds = _adjust_fraction_of_nanoseconds(
                value, max_fraction, scale
            )

            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        def conv(encoded_value: str) -> str:
            value, tz = encoded_value.split()
            microseconds = float(value[0 : -scale + 6])
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            try:
                t = datetime.fromtimestamp(microseconds, tz=tzinfo)
            except (OSError, ValueError) as e:
                logger.debug("OSError occurred but falling back to datetime: %s", e)
                t = ZERO_EPOCH + timedelta(seconds=microseconds)
                if pytz.utc != tzinfo:
                    t += tzinfo.utcoffset(t)
                t = t.replace(tzinfo=tzinfo)

            fraction_of_nanoseconds = _adjust_fraction_of_nanoseconds(
                value, max_fraction, scale
            )

            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_LTZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        def conv(value: str) -> str:
            t, fraction_of_nanoseconds = self._pre_TIMESTAMP_LTZ_to_python(value, ctx)
            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_NTZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        """Converts TIMESTAMP NTZ to Snowflake Formatted String.

        No timezone info is attached.
        """

        def conv(value: str) -> str:
            try:
                # flot loses precision when the interger part is way larger than the
                # decimal part. this is a limitation by Python float number
                # e.g. 253402300799.999999 will just be 253402300800.0
                # so we need to separately extract seconds, microseconds part
                (
                    fractions_of_seconds,
                    fractions_of_microseconds,
                    fraction_of_nanoseconds,
                ) = _extract_timestamp_snowsql(value, ctx)
                t = ZERO_EPOCH + timedelta(
                    seconds=fractions_of_seconds, microseconds=fractions_of_microseconds
                )
                return format_sftimestamp(ctx, t, fraction_of_nanoseconds)
            except OverflowError as e:
                # timedelta and handle time <= 9999-12-31 23:59:59, however, beyond this point datetime will be out
                # of range, we use time.gmtime to handle data
                # in this case we can not yet handle the precision lost issue, but it should really be a corner case
                logger.debug(
                    "OverflowError occurred but falling back to time.gmtime: %s", e
                )
                microseconds, fraction_of_nanoseconds = _extract_timestamp(value, ctx)
                return format_sftimestamp(
                    ctx, time.gmtime(microseconds), fraction_of_nanoseconds
                )

        return conv

    _TIME_to_python = _TIMESTAMP_NTZ_to_python
