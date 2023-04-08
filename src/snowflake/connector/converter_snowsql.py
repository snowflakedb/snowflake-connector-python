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
    _generate_tzinfo_from_tzoffset,
)
from .sfbinaryformat import SnowflakeBinaryFormat, binary_to_python
from .sfdatetime import SnowflakeDateFormat, SnowflakeDateTime, SnowflakeDateTimeFormat

MICROSECONDS_ZERO_FILL = "000000"
ONE_DAY_SECONDS = 24 * 60 * 60

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
            return ctx["fmt"].format(time.gmtime(int(value) * (ONE_DAY_SECONDS)))

        def conv_windows(value):
            ts = ZERO_EPOCH + timedelta(seconds=int(value) * (ONE_DAY_SECONDS))
            return ctx["fmt"].format(date(ts.year, ts.month, ts.day))

        return conv if not IS_WINDOWS else conv_windows

    def _TIMESTAMP_TZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        """Converts TIMESTAMP TZ to datetime.

        The timezone offset is piggybacked.
        """
        scale = ctx["scale"]
        max_fraction = ctx.get("max_fraction")

        def conv(encoded_value: str) -> str:
            value, tz = encoded_value.split()
            (
                fractions_of_seconds,
                fractions_of_microseconds,
                fraction_of_nanoseconds,
            ) = _extract_timestamp_snowsql(value, ctx)
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            compensate_seconds = 0
            try:
                t = ZERO_EPOCH + timedelta(
                    seconds=fractions_of_seconds, microseconds=fractions_of_microseconds
                )
            except OverflowError:
                # for TIMESTAMP_TZ, we can assume the time part of all datetime will be <= 9999/12/31, while
                # the timezone can be different
                # time like 9999-12-31 23:59:59.999 -1200 will return timestamp value which causes datetime overflow
                # in this case, we use a trick to first reduce the seconds by one day to make datetime can be
                # constructed from the timestamp and set tz accordingly.
                # After the construction of the datetime, we add the one-day back, so we bypass the overflow issue
                t = ZERO_EPOCH + timedelta(
                    seconds=fractions_of_seconds - ONE_DAY_SECONDS,
                    microseconds=fractions_of_microseconds,
                )
                compensate_seconds = ONE_DAY_SECONDS
            if pytz.utc != tzinfo:
                t += tzinfo.utcoffset(t)
            t = t.replace(tzinfo=tzinfo)
            t = t + timedelta(seconds=compensate_seconds)  # add back the reduced 1 day
            fraction_of_nanoseconds = _adjust_fraction_of_nanoseconds(
                value, max_fraction, scale
            )

            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_LTZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        def conv(value: str) -> str:
            print(value)
            (
                fractions_of_seconds,
                fractions_of_microseconds,
                fraction_of_nanoseconds,
            ) = _extract_timestamp_snowsql(value, ctx)
            tzinfo_value = self._get_session_tz()
            try:
                t0 = ZERO_EPOCH + timedelta(
                    seconds=fractions_of_seconds, microseconds=fractions_of_microseconds
                )
                t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo_value)
            except OverflowError:
                logger.debug(
                    "OverflowError in converting from epoch time to "
                    "timestamp_ltz: %s(ms). Falling back to use struct_time."
                )
                # handling overflow in TIMESTAMP_LTZ is different from TIMESTAMP_TZ
                # we can assume all the date no matter of which tz of TIMESTAMP_TZ will be <= 9999/12/31 23:59:59
                # so we can perform the -1 day operation
                # however we can not performa the safe strategy here because the timestamp value
                # can be > 9999/12/31 23:59:59 when converted to local time leading to overflow
                # and to avoid breaking change and be compatible with the previous behavior
                # we keep using time.localtime

                # localtime can not handle decimal seconds
                # it's okay to ignore microseconds which will be handled by format_sftimestamp
                t = time.localtime(fractions_of_seconds)
            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_NTZ_to_python(self, ctx: dict[str, Any]) -> Callable:
        """Converts TIMESTAMP NTZ to Snowflake Formatted String.

        No timezone info is attached.
        """

        def conv(value: str) -> str:
            print(value)
            (
                fractions_of_seconds,
                fractions_of_microseconds,
                fraction_of_nanoseconds,
            ) = _extract_timestamp_snowsql(value, ctx)
            t = ZERO_EPOCH + timedelta(
                seconds=fractions_of_seconds, microseconds=fractions_of_microseconds
            )
            return format_sftimestamp(ctx, t, fraction_of_nanoseconds)

        return conv

    _TIME_to_python = _TIMESTAMP_NTZ_to_python
