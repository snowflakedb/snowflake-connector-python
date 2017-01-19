#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import time
from datetime import timedelta, date
from logging import getLogger

from .compat import TO_UNICODE
from .converter import (SnowflakeConverter, ZERO_EPOCH)
from .sfbinaryformat import (binary_to_python, SnowflakeBinaryFormat)
from .sfdatetime import (SnowflakeDateTimeFormat, SnowflakeDateTime)

logger = getLogger(__name__)


def _format_sftimestamp(fmt, value, franction_of_nanoseconds):
    if fmt:
        return SnowflakeDateTimeFormat(fmt).format(
            SnowflakeDateTime(
                value, nanosecond=franction_of_nanoseconds))
    return TO_UNICODE(SnowflakeDateTime(
        value, nanosecond=franction_of_nanoseconds))


class SnowflakeConverterSnowSQL(SnowflakeConverter):
    """
    Snowflake Converter for SnowSQL.

    Format data instead of just converting the values into native
    Python objects.
    """

    def __init__(self, **kwargs):
        super(SnowflakeConverterSnowSQL, self).__init__(
            use_sfbinaryformat=True)
        logger.info('initialized')

    def _get_format(self, type_name):
        """
        Gets the format
        """
        fmt = None
        if type_name == u'DATE':
            fmt = self._parameters.get(u'DATE_OUTPUT_FORMAT')
        elif type_name == u'TIME':
            fmt = self._parameters.get(u'TIME_OUTPUT_FORMAT')
        elif type_name + u'_OUTPUT_FORMAT' in self._parameters:
            fmt = self._parameters[type_name + u'_OUTPUT_FORMAT']
            if not fmt:
                fmt = self._parameters[u'TIMESTAMP_OUTPUT_FORMAT']
        elif type_name == u'BINARY':
            fmt = self._parameters.get(u'BINARY_OUTPUT_FORMAT')
        return fmt

    #
    # FROM Snowflake to Python objects
    #
    def to_python_method(self, type_name, row_type):
        try:
            return getattr(self, u'_{type_name}_to_python'.format(
                type_name=type_name)), self._get_format(type_name)
        except KeyError:
            # no type is defined, pass through it
            return self._TEXT_to_python, None

    def _BOOLEAN_to_python(self, value, *_):
        """
        No conversion for SnowSQL
        """
        return u"True" if value in (u'1', u"True") else u"False"

    def _FIXED_to_python(self, value, *_):
        """
        No conversion for SnowSQL
        """
        return value

    def _REAL_to_python(self, value, *_):
        """
        No conversion for SnowSQL
        """
        return value

    def _BINARY_to_python(self, value, _, fmt):
        """
        BINARY to a string formatted by BINARY_OUTPUT_FORMAT
        """
        bytes_value = binary_to_python(value)
        return SnowflakeBinaryFormat(fmt).format(bytes_value)

    def _DATE_to_python(self, value, _, fmt):
        """
        DATE to datetime

        No timezone is attached.
        """
        try:
            t = ZERO_EPOCH + timedelta(seconds=int(value) * (24 * 60 * 60))
            if fmt:
                return SnowflakeDateTimeFormat(fmt).format(t)
            return TO_UNICODE(date(t.year, t.month, t.day))
        except OverflowError:
            self.logger.debug(
                "OverflowError in converting from epoch time to date: %s(s). "
                "Falling back to use struct_time.",
                value)
            t = time.gmtime(value)
            if fmt:
                return SnowflakeDateTimeFormat(fmt).format(
                    SnowflakeDateTime(t, nanosecond=0)
                )
            return u'{year:d}-{month:02d}-{day:02d}'.format(
                year=t.tm_year, month=t.tm_mon, day=t.tm_mday)

    def _TIMESTAMP_TZ_to_python(self, value, col_desc, fmt):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """
        t, fraction_of_nanoseconds = self._pre_TIMESTAMP_TZ_to_python(
            value, col_desc)
        return _format_sftimestamp(fmt, t, fraction_of_nanoseconds)

    def _TIMESTAMP_LTZ_to_python(self, value, col_desc, fmt):
        t, fraction_of_nanoseconds = self._pre_TIMESTAMP_LTZ_to_python(
            value, col_desc)
        return _format_sftimestamp(fmt, t, fraction_of_nanoseconds)

    def _TIMESTAMP_NTZ_to_python(self, value, col_desc, fmt):
        """
        TIMESTAMP NTZ to Snowflake Formatted String

        No timezone info is attached.
        """
        _, microseconds, fraction_of_nanoseconds = \
            self._pre_TIMESTAMP_NTZ_to_python(value, col_desc)
        if microseconds is None:
            return None
        try:
            t = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
        except OverflowError:
            self.logger.debug(
                "OverflowError in converting from epoch time to datetime: %s("
                "ms). Falling back to use struct_time.",
                microseconds)
            t = time.gmtime(microseconds / float(1000000))
        return _format_sftimestamp(fmt, t, fraction_of_nanoseconds)

    def _TIME_to_python(self, value, col_desc, fmt):
        """
        TIME to formatted string, SnowflakeDateTime, or datetime.time

        No timezone is attached.
        """
        microseconds, fraction_of_nanoseconds = \
            self._extract_time(value, col_desc)

        try:
            t = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
        except OverflowError:
            self.logger.debug(
                "OverflowError in converting from epoch time to datetime: %s("
                "ms). Falling back to use struct_time.",
                microseconds)
            t = time.gmtime(microseconds / float(1000000))
        return _format_sftimestamp(fmt, t, fraction_of_nanoseconds)
