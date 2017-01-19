#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import decimal
import time
from datetime import datetime, timedelta, tzinfo, date
from logging import getLogger

import pytz

from .compat import (IS_BINARY, TO_UNICODE, IS_NUMERIC)
from .errorcode import (ER_NOT_SUPPORT_DATA_TYPE)
from .errors import (ProgrammingError)
from .sfbinaryformat import (binary_to_python,
                             binary_to_snowflake)
from .sfdatetime import (sfdatetime_total_seconds_from_timedelta,
                         sfdatetime_to_snowflake)

try:
    import numpy
except:
    numpy = None

BITS_FOR_TIMEZONE = 14
MASK_OF_TIMEZONE = int((1 << BITS_FOR_TIMEZONE) - 1)
ZERO_TIMEDELTA = timedelta(seconds=0)
ZERO_EPOCH = datetime.utcfromtimestamp(0)

# Tzinfo class cache
_TZINFO_CLASS_CACHE = {}


class SnowflakeConverter(object):
    def __init__(self, **kwargs):
        self._parameters = {}
        self._use_sfbinaryformat = kwargs.get('use_sfbinaryformat', False)
        self._use_numpy = kwargs.get('use_numpy', False) and numpy is not None

        self.logger = getLogger(__name__)
        self.logger.info('use_sfbinaryformat: %s, use_numpy: %s',
                         self._use_sfbinaryformat,
                         self._use_numpy)

    def set_parameters(self, parameters):
        self._parameters = {}
        for kv in parameters:
            self._parameters[kv[u'name']] = kv[u'value']

    def set_parameter(self, param, value):
        self._parameters[param] = value

    def get_parameters(self):
        return self._parameters

    def get_parameter(self, param):
        return self._parameters[param] if param in self._parameters else None

    def _generate_tzinfo_from_tzoffset(self, tzoffset_minutes):
        """
        Generates tzinfo object from tzoffset.
        """
        if str(tzoffset_minutes) in _TZINFO_CLASS_CACHE:
            return _TZINFO_CLASS_CACHE[str(tzoffset_minutes)]

        sign = u'P' if tzoffset_minutes >= 0 else u'N'
        abs_tzoffset_minutes = abs(tzoffset_minutes)
        hour, minute = divmod(abs_tzoffset_minutes, 60)
        name = u'GMT{sign:s}{hour:02d}{minute:02d}'.format(
            sign=sign,
            hour=hour,
            minute=minute)
        tzinfo_class_type = type(
            str(name),  # str() for both Python 2 and 3
            (tzinfo,),
            dict(
                utcoffset=lambda self0, dt, is_dst=False: timedelta(
                    minutes=tzoffset_minutes),
                tzname=lambda self0, dt: name,
                dst=lambda self0, dt: ZERO_TIMEDELTA
            )
        )
        tzinfo_cls = tzinfo_class_type()
        _TZINFO_CLASS_CACHE[str(tzoffset_minutes)] = tzinfo_cls
        return tzinfo_cls

    #
    # FROM Snowflake to Python Objects
    #
    def to_python_method(self, type_name, row_type):
        try:
            if self._use_numpy:
                return getattr(self, u'_{type_name}_numpy_to_python'.format(
                    type_name=type_name)), None
            elif type_name == 'FIXED' and row_type['scale'] == 0:
                return self._FIXED_INT_to_python, None
            else:
                return getattr(self, u'_{type_name}_to_python'.format(
                    type_name=type_name)), None
        except KeyError:
            # no type is defined
            return self._str_to_snowflake, None

    def _FIXED_INT_to_python(self, value, *_):
        return int(value)

    def _FIXED_to_python(self, value, *_):
        return decimal.Decimal(value)

    def _FIXED_numpy_to_python(self, value, *_):
        return numpy.int64(value)

    def _REAL_to_python(self, value, *_):
        return float(value)

    def _REAL_numpy_to_python(self, value, *_):
        return numpy.float64(value)

    def _TEXT_to_python(self, value, *_):
        return value

    _TEXT_numpy_to_python = _TEXT_to_python

    def _BINARY_to_python(self, value, *_):
        return binary_to_python(value)

    _BINARY_numpy_to_python = _BINARY_to_python

    def _DATE_to_python(self, value, *_):
        """
        DATE to datetime

        No timezone is attached.
        """
        ts = ZERO_EPOCH + timedelta(seconds=int(value) * (24 * 60 * 60))
        return date(ts.year, ts.month, ts.day)

    def _DATE_numpy_to_python(self, value, *_):
        """
        DATE to datetime

        No timezone is attached.
        """
        return numpy.datetime64(int(value), 'D')

    def _extract_timestamp(self, value, col_desc, has_tz=False):
        """Extracts timstamp from a raw data
        """
        scale = col_desc[5]
        try:
            value1 = decimal.Decimal(value)
            big_int = int(value1.scaleb(scale))  # removed fraction

            if has_tz:
                tzoffset = (big_int & MASK_OF_TIMEZONE) - 1440
                secs_wo_tz_off = (big_int >> BITS_FOR_TIMEZONE)
            else:
                tzoffset = 0
                secs_wo_tz_off = big_int

            nanoseconds = secs_wo_tz_off * 10 ** (9 - scale)
            microseconds = nanoseconds // 1000

            fraction_of_nanoseconds = nanoseconds % 1000000000
            return tzoffset, microseconds, fraction_of_nanoseconds, nanoseconds
        except decimal.InvalidOperation:
            return None, None, None

    def _pre_TIMESTAMP_TZ_to_python(self, value, col_desc):
        u"""
        try to split value by space for handling new timestamp with timezone
        encoding format which has timezone index separate from the timestamp
        value
        """

        tzoffset_extracted = None

        valueComponents = str(value).split(" ")
        if len(valueComponents) == 2:
            tzoffset_extracted = int(valueComponents[1]) - 1440
            value = valueComponents[0]

        tzoffset, microseconds, fraction_of_nanoseconds, nanoseconds = \
            self._extract_timestamp(value, col_desc,
                                    has_tz=(tzoffset_extracted is None))

        if tzoffset_extracted is not None:
            tzoffset = tzoffset_extracted

        if tzoffset is None:
            return None

        tzinfo_value = self._generate_tzinfo_from_tzoffset(tzoffset)

        t = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
        if pytz.utc != tzinfo_value:
            t += tzinfo_value.utcoffset(t, is_dst=False)
        return t.replace(tzinfo=tzinfo_value), fraction_of_nanoseconds

    def _TIMESTAMP_TZ_to_python(self, value, col_desc, *_):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """
        t, _ = self._pre_TIMESTAMP_TZ_to_python(value, col_desc)
        return t

    def _TIMESTAMP_TZ_numpy_to_python(self, value, col_desc, *_):
        """TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """
        t, fraction_of_nanoseconds = self._pre_TIMESTAMP_TZ_to_python(
            value, col_desc)
        ts = int(time.mktime(t.timetuple())) * 1000000000 + int(
            fraction_of_nanoseconds)
        return numpy.datetime64(ts, 'ns')

    def _pre_TIMESTAMP_LTZ_to_python(self, value, col_desc):
        u""" TIMESTAMP LTZ to datetime

        This takes consideration of the session parameter TIMEZONE if
        available. If not, tzlocal is used
        """
        tzoffset, microseconds, fraction_of_nanoseconds, nanoseconds = \
            self._extract_timestamp(value, col_desc)
        if tzoffset is None:
            return None
        try:
            tzinfo_value = pytz.timezone(self.get_parameter(u'TIMEZONE'))
        except pytz.exceptions.UnknownTimeZoneError:
            self.logger.warn('converting to tzinfo_value failed')
            try:
                # tzlocal is optional.
                import tzlocal
                tzinfo_value = tzlocal.get_localzone()
            except:
                tzinfo_value = pytz.timezone('UTC')

        try:
            t0 = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
            t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo_value)
            return t, fraction_of_nanoseconds
        except OverflowError:
            self.logger.debug(
                "OverflowError in converting from epoch time to "
                "timestamp_ltz: %s(ms). Falling back to use struct_time."
            )
            t = time.gmtime(microseconds / float(1000000))
            return t, fraction_of_nanoseconds

    def _TIMESTAMP_LTZ_to_python(self, value, col_desc, *_):
        t, _ = self._pre_TIMESTAMP_LTZ_to_python(value, col_desc)
        return t

    def _TIMESTAMP_LTZ_numpy_to_python(self, value, col_desc, *_):
        t, fraction_of_nanoseconds = self._pre_TIMESTAMP_LTZ_to_python(
            value, col_desc)
        ts = int(time.mktime(t.timetuple())) * 1000000000 + int(
            fraction_of_nanoseconds)
        return numpy.datetime64(ts, 'ns')

    _TIMESTAMP_to_python = _TIMESTAMP_LTZ_to_python

    def _pre_TIMESTAMP_NTZ_to_python(self, value, col_desc):
        """TIMESTAMP NTZ to datetime

        No timezone info is attached.
        """
        tzoffset, microseconds, fraction_of_nanoseconds, nanoseconds = \
            self._extract_timestamp(value, col_desc)

        if tzoffset is None:
            return None, None, None

        return nanoseconds, microseconds, fraction_of_nanoseconds

    def _TIMESTAMP_NTZ_to_python(self, value, col_desc, *_):
        """
        TIMESTAMP NTZ to datetime

        No timezone info is attached.
        """
        _, microseconds, _ = self._pre_TIMESTAMP_NTZ_to_python(value, col_desc)
        if microseconds is None:
            return None

        # NOTE: date range must fit into datetime data type or will raise
        # OverflowError
        t = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
        return t

    def _TIMESTAMP_NTZ_numpy_to_python(self, value, col_desc, *_):
        """
        TIMESTAMP NTZ to datetime64

        No timezone info is attached.
        """
        nanoseconds, _, _ = self._pre_TIMESTAMP_NTZ_to_python(value, col_desc)
        return numpy.datetime64(nanoseconds, 'ns')

    def _extract_time(self, value, col_desc):
        u"""Extracts time from raw data

        Returns a pair containing microseconds since midnight and nanoseconds
        since the last whole-numebr second. The last 6 digits of microseconds
        will be the same as the first 6 digits of nanoseconds.
        """
        scale = col_desc[5]
        try:
            value1 = decimal.Decimal(value)
            big_int = int(value1.scaleb(scale))  # removed fraction

            nanoseconds = big_int * 10 ** (9 - scale)
            microseconds = nanoseconds // 1000

            fraction_of_nanoseconds = nanoseconds % 1000000000
            return microseconds, fraction_of_nanoseconds
        except decimal.InvalidOperation:
            return None, None

    def _TIME_to_python(self, value, col_desc, *_):
        """
        TIME to formatted string, SnowflakeDateTime, or datetime.time

        No timezone is attached.
        """
        microseconds, _ = self._extract_time(value, col_desc)
        ts = ZERO_EPOCH + timedelta(seconds=(microseconds / float(1000000)))
        return ts.time()

    _TIME_numpy_to_python = _TIME_to_python

    def _VARIANT_to_python(self, value, *_):
        return value

    _VARIANT_numpy_to_python = _VARIANT_to_python

    def _OBJECT_to_python(self, value, col_desc, *_):
        return self._VARIANT_to_python(value, col_desc)

    _OBJECT_numpy_to_python = _OBJECT_to_python

    def _ARRAY_to_python(self, value, col_desc, *_):
        return self._VARIANT_to_python(value, col_desc)

    _ARRAY_numpy_to_python = _ARRAY_to_python

    def _BOOLEAN_to_python(self, value, *_):
        return value in (u'1', u'TRUE')

    _BOOLEAN_numpy_to_python = _BOOLEAN_to_python

    #
    # From Python to Snowflake
    #
    def to_snowflake(self, value):
        type_name = value.__class__.__name__.lower()
        return getattr(self, u"_{type_name}_to_snowflake".format(
            type_name=type_name))(value)

    def _int_to_snowflake(self, value):
        return int(value)

    def _long_to_snowflake(self, value):
        return long(value)

    def _float_to_snowflake(self, value):
        return float(value)

    def _str_to_snowflake(self, value):
        return TO_UNICODE(value)

    def _unicode_to_snowflake(self, value):
        return TO_UNICODE(value)

    def _bytes_to_snowflake(self, value):
        return binary_to_snowflake(value)

    def _bytearray_to_snowflake(self, value):
        return binary_to_snowflake(value)

    def _bool_to_snowflake(self, value):
        return value

    def _nonetype_to_snowflake(self, value):
        del value
        return None

    def _total_seconds_from_timedelta(self, td):
        return sfdatetime_total_seconds_from_timedelta(td)

    def _datetime_to_snowflake(self, value):
        tzinfo_value = value.tzinfo
        if tzinfo_value:
            if pytz.utc != tzinfo_value:
                td = tzinfo_value.utcoffset(value, is_dst=False)
            else:
                td = ZERO_TIMEDELTA
            sign = u'+' if td >= ZERO_TIMEDELTA else u'-'
            td_secs = sfdatetime_total_seconds_from_timedelta(td)
            h, m = divmod(abs(td_secs // 60), 60)
            if value.microsecond:
                return (
                    u'{year:d}-{month:02d}-{day:02d} '
                    u'{hour:02d}:{minute:02d}:{second:02d}.'
                    u'{microsecond:06d}{sign}{tzh:02d}:{tzm:02d}').format(
                    year=value.year, month=value.month, day=value.day,
                    hour=value.hour, minute=value.minute,
                    second=value.second,
                    microsecond=value.microsecond, sign=sign, tzh=h,
                    tzm=m
                )
            return (
                u'{year:d}-{month:02d}-{day:02d} '
                u'{hour:02d}:{minute:02d}:{second:02d}'
                u'{sign}{tzh:02d}:{tzm:02d}').format(
                year=value.year, month=value.month, day=value.day,
                hour=value.hour, minute=value.minute,
                second=value.second,
                sign=sign, tzh=h, tzm=m
            )
        else:
            if value.microsecond:
                return (u'{year:d}-{month:02d}-{day:02d} '
                        u'{hour:02d}:{minute:02d}:{second:02d}.'
                        u'{microsecond:06d}').format(
                    year=value.year, month=value.month, day=value.day,
                    hour=value.hour, minute=value.minute,
                    second=value.second,
                    microsecond=value.microsecond
                )
            return (u'{year:d}-{month:02d}-{day:02d} '
                    u'{hour:02d}:{minute:02d}:{second:02d}').format(
                year=value.year, month=value.month, day=value.day,
                hour=value.hour, minute=value.minute,
                second=value.second
            )

    def _sfdatetime_to_snowflake(self, value):
        return sfdatetime_to_snowflake(value)

    def date_to_snowflake(self, value):
        """
        Converts Date object to Snowflake object
        """
        return self._date_to_snowflake(value)

    def _date_to_snowflake(self, value):
        return u'{year:d}-{month:02d}-{day:02d}'.format(year=value.year,
                                                        month=value.month,
                                                        day=value.day)

    def _time_to_snowflake(self, value):
        if value.microsecond:
            return value.strftime(u'%H:%M:%S.%%06d') % value.microsecond
        return value.strftime(u'%H:%M:%S')

    def _struct_time_to_snowflake(self, value):
        tzinfo_value = self._generate_tzinfo_from_tzoffset(
            -time.timezone // 60)
        t = datetime.fromtimestamp(time.mktime(value))
        if pytz.utc != tzinfo_value:
            t += tzinfo_value.utcoffset(t)
        t = t.replace(tzinfo=tzinfo_value)

        return self._datetime_to_snowflake(t)

    def _timedelta_to_snowflake(self, value):
        (hours, r) = divmod(value.seconds, 3600)
        (mins, secs) = divmod(r, 60)
        hours += value.days * 24
        if value.microseconds:
            return (u'{hour:02d}:{minute:02d}:{second:02d}.'
                    u'{microsecond:06d}').format(
                hour=hours, minute=mins,
                second=secs,
                microsecond=value.microseconds)
        return u'{hour:02d}:{minute:02d}:{second:02d}'.format(hour=hours,
                                                              minute=mins,
                                                              second=secs)

    def _decimal_to_snowflake(self, value):
        if isinstance(value, decimal.Decimal):
            return TO_UNICODE(value)

        return None

    def _list_to_snowflake(self, value):
        return [SnowflakeConverter.quote(v0) for v0 in
                [SnowflakeConverter.escape(v) for v in value]]

    _tuple_to_snowflake = _list_to_snowflake

    def __numpy_to_snowflake(self, value):
        return value

    _int8_to_snowflake = __numpy_to_snowflake
    _int16_to_snowflake = __numpy_to_snowflake
    _int32_to_snowflake = __numpy_to_snowflake
    _int64_to_snowflake = __numpy_to_snowflake
    _uint8_to_snowflake = __numpy_to_snowflake
    _uint16_to_snowflake = __numpy_to_snowflake
    _uint32_to_snowflake = __numpy_to_snowflake
    _uint64_to_snowflake = __numpy_to_snowflake
    _float16_to_snowflake = __numpy_to_snowflake
    _float32_to_snowflake = __numpy_to_snowflake
    _float64_to_snowflake = __numpy_to_snowflake

    def _datetime64_to_snowflake(self, value):
        return TO_UNICODE(value)

    def _quoted_name_to_snowflake(self, value):
        return TO_UNICODE(value)

    def __getattr__(self, item):
        if item.endswith('_to_snowflake'):
            raise ProgrammingError(
                msg=u"Binding data in type ({0}) is not supported.".format(
                    item[1:item.find('_to_snowflake')]),
                errno=ER_NOT_SUPPORT_DATA_TYPE
            )
        raise Exception('No method is available: {0}'.format(item))

    @staticmethod
    def escape(value):
        if isinstance(value, list):
            return value
        if value is None or IS_NUMERIC(value) or IS_BINARY(value):
            return value
        res = value
        res = res.replace(u'\\', u'\\\\')
        res = res.replace(u'\n', u'\\n')
        res = res.replace(u'\r', u'\\r')
        res = res.replace(u'\047', u'\134\047')  # single quotes
        return res

    @staticmethod
    def quote(value):
        if isinstance(value, list):
            return ','.join(value)
        if value is None:
            return u'NULL'
        elif isinstance(value, bool):
            return u'TRUE' if value else u'FALSE'
        elif IS_NUMERIC(value):
            return TO_UNICODE(repr(value))
        elif IS_BINARY(value):
            # Binary literal syntax
            return u"X'{0}'".format(value.decode('ascii'))

        return u"'{0}'".format(value)
