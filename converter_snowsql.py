#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import time
from datetime import timedelta, datetime, date
from logging import getLogger

from .compat import TO_UNICODE
from .constants import is_timestamp_type_name
from .converter import (SnowflakeConverter, ZERO_EPOCH)
from .sfbinaryformat import (binary_to_python, SnowflakeBinaryFormat)
from .sfdatetime import (SnowflakeDateTimeFormat, SnowflakeDateTime)

logger = getLogger(__name__)


def format_sftimestamp(fmt, value, franction_of_nanoseconds):
    sf_datetime = SnowflakeDateTime(value, nanosecond=franction_of_nanoseconds)
    return fmt.format(sf_datetime) if fmt else TO_UNICODE(sf_datetime)


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
            if not fmt:
                fmt = u'YYYY-MM-DD'
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
    def to_python_method(self, type_name, column):
        ctx = column.copy()
        if ctx.get('scale'):
            ctx['max_fraction'] = int(10 ** ctx['scale'])
            ctx['zero_fill'] = '0' * (9 - ctx['scale'])
        fmt = None
        if is_timestamp_type_name(type_name):
            fmt = SnowflakeDateTimeFormat(
                self._get_format(type_name),
                datetime_class=SnowflakeDateTime)
        elif type_name == u'BINARY':
            fmt = SnowflakeBinaryFormat(self._get_format(type_name))
        logger.debug('Type: %s, Format: %s', type_name, fmt)
        ctx['fmt'] = fmt
        converters = [u'_{type_name}_to_python'.format(type_name=type_name)]
        for conv in converters:
            try:
                return getattr(self, conv)(ctx)
            except AttributeError:
                pass
        self.logger.warn("No column converter found for type: %s", type_name)
        return None  # Skip conversion

    def _BOOLEAN_to_python(self, ctx):
        """
        No conversion for SnowSQL
        """
        return lambda value: "True" if value in (u'1', u"True") else u"False"

    def _FIXED_to_python(self, ctx):
        """
        No conversion for SnowSQL
        """
        return None

    def _REAL_to_python(self, ctx):
        """
        No conversion for SnowSQL
        """
        return None

    def _BINARY_to_python(self, ctx):
        """
        BINARY to a string formatted by BINARY_OUTPUT_FORMAT
        """
        return lambda value: ctx['fmt'].format(binary_to_python(value))

    def _DATE_to_python(self, ctx):
        """
        DATE to datetime

        No timezone is attached.
        """

        def conv(value):
            try:
                t = datetime.utcfromtimestamp(int(value) * 86400).date()
            except OSError as e:
                self.logger.debug("Failed to convert: %s", e)
                ts = ZERO_EPOCH + timedelta(
                    seconds=int(value) * (24 * 60 * 60))
                t = date(ts.year, ts.month, ts.day)
            return ctx['fmt'].format(SnowflakeDateTime(t, nanosecond=0))

        return conv

    def _TIMESTAMP_TZ_to_python(self, ctx):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """

        scale = ctx['scale']
        max_fraction = ctx.get('max_fraction')

        def conv0(encoded_value):
            value, tz = encoded_value.split()
            microseconds = float(value)
            tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(
                int(tz) - 1440)
            t = datetime.fromtimestamp(microseconds, tz=tzinfo)
            if scale == 0:
                fraction_of_nanoseconds = 0
            else:
                fraction_of_nanoseconds = int(value[-scale:])
                if value[0] == '-':
                    fraction_of_nanoseconds = max_fraction - fraction_of_nanoseconds

            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        def conv(encoded_value):
            value, tz = encoded_value.split()
            microseconds = float(value[0:-scale + 6])
            tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(
                int(tz) - 1440)
            t = datetime.fromtimestamp(microseconds, tz=tzinfo)
            if scale == 0:
                fraction_of_nanoseconds = 0
            else:
                fraction_of_nanoseconds = int(value[-scale:])
                if value[0] == '-':
                    fraction_of_nanoseconds = max_fraction - fraction_of_nanoseconds

            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        def conv(value):
            t, _, fraction_of_nanoseconds = self._pre_TIMESTAMP_LTZ_to_python(
                value, ctx)
            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """
        TIMESTAMP NTZ to Snowflake Formatted String

        No timezone info is attached.
        """

        def conv(value):
            microseconds, _, fraction_of_nanoseconds = \
                self._extract_timestamp(value, ctx)
            try:
                t = ZERO_EPOCH + timedelta(seconds=(microseconds))
            except OverflowError:
                self.logger.debug(
                    "OverflowError in converting from epoch time to datetime:"
                    " %s(ms). Falling back to use struct_time.",
                    microseconds)
                t = time.gmtime(microseconds)
            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv

    _TIME_to_python = _TIMESTAMP_NTZ_to_python
