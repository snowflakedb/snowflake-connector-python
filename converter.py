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
except ImportError:
    numpy = None
try:
    import tzlocal
except ImportError:
    tzlocal = None

BITS_FOR_TIMEZONE = 14
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
        self.logger.debug('use_sfbinaryformat: %s, use_numpy: %s',
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

    @staticmethod
    def _generate_tzinfo_from_tzoffset(tzoffset_minutes):
        """
        Generates tzinfo object from tzoffset.
        """
        try:
            return _TZINFO_CLASS_CACHE[tzoffset_minutes]
        except KeyError:
            pass
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
        _TZINFO_CLASS_CACHE[tzoffset_minutes] = tzinfo_cls
        return tzinfo_cls

    #
    # FROM Snowflake to Python Objects
    #
    def to_python_method(self, type_name, column):
        ctx = column.copy()
        if ctx.get('scale'):
            ctx['max_fraction'] = int(10 ** ctx['scale'])
            ctx['zero_fill'] = '0' * (9 - ctx['scale'])
        converters = [u'_{type_name}_to_python'.format(type_name=type_name)]
        if self._use_numpy:
            converters.insert(0, u'_{type_name}_numpy_to_python'.format(
                type_name=type_name))
        for conv in converters:
            try:
                return getattr(self, conv)(ctx)
            except AttributeError:
                pass
        self.logger.warning(
            "No column converter found for type: %s", type_name)
        return None  # Skip conversion

    def _FIXED_to_python(self, ctx):
        return int if ctx['scale'] == 0 else decimal.Decimal

    def _FIXED_numpy_to_python(self, ctx):
        if ctx['scale']:
            return decimal.Decimal
        else:

            def conv(value):
                try:
                    return numpy.int64(value)
                except OverflowError:
                    return int(value)

            return conv

    def _REAL_to_python(self, _):
        return float

    def _REAL_numpy_to_python(self, _):
        return numpy.float64

    def _TEXT_to_python(self, _):
        return None  # skip conv

    def _BINARY_to_python(self, _):
        return binary_to_python

    def _DATE_to_python(self, _):
        """
        DATE to datetime

        No timezone is attached.
        """

        def conv(value):
            try:
                return datetime.utcfromtimestamp(int(value) * 86400).date()
            except OSError as e:
                self.logger.debug("Failed to convert: %s", e)
                ts = ZERO_EPOCH + timedelta(
                    seconds=int(value) * (24 * 60 * 60))
                return date(ts.year, ts.month, ts.day)

        return conv

    def _DATE_numpy_to_python(self, _):
        """
        DATE to datetime

        No timezone is attached.
        """
        return lambda x: numpy.datetime64(int(x), 'D')

    def _extract_timestamp(self, value, ctx):
        """
        Extracts timestamp from a raw data
        """
        scale = ctx['scale']
        microseconds = float(
            value[0:-scale + 6]) if scale > 6 else float(value)
        is_negative = value[0] == '-'
        if scale == 0:
            fraction_of_nanoseconds = 0
        else:
            max_fraction = ctx['max_fraction']
            fraction_of_nanoseconds = int(value[-scale:])
            if is_negative and fraction_of_nanoseconds > 0:
                fraction_of_nanoseconds = max_fraction - fraction_of_nanoseconds

        return microseconds, is_negative, fraction_of_nanoseconds

    def _pre_TIMESTAMP_TZ_to_python(self, encoded_value, ctx):
        """
        try to split value by space for handling new timestamp with timezone
        encoding format which has timezone index separate from the timestamp
        value
        """
        value, tz = encoded_value.split()
        microseconds, is_negative, fraction_of_nanoseconds = \
            self._extract_timestamp(value, ctx)
        tzinfo_value = SnowflakeConverter._generate_tzinfo_from_tzoffset(
            int(tz) - 1440)

        t = ZERO_EPOCH + timedelta(seconds=(microseconds))
        if pytz.utc != tzinfo_value:
            t += tzinfo_value.utcoffset(t, is_dst=False)
        return t.replace(tzinfo=tzinfo_value), \
               is_negative, fraction_of_nanoseconds

    def _TIMESTAMP_TZ_to_python(self, ctx):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """

        scale = ctx['scale']

        def conv0(encoded_value):
            value, tz = encoded_value.split()
            tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(
                int(tz) - 1440)
            return datetime.fromtimestamp(float(value), tz=tzinfo)

        def conv(encoded_value):
            value, tz = encoded_value.split()
            microseconds = float(value[0:-scale + 6])
            tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(
                int(tz) - 1440)
            return datetime.fromtimestamp(microseconds, tz=tzinfo)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_TZ_numpy_to_python(self, ctx):
        """TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """
        scale = ctx['scale']
        zero_fill = ctx['zero_fill']

        def conv0(encoded_value):
            value, tz = encoded_value.split()
            ts = 60 * (int(tz) - 1440) + int(value)
            return numpy.datetime64(ts, 's')

        def conv(encoded_value):
            value, tz = encoded_value.split()
            ts = (60 * (int(tz) - 1440) + int(value[0:-scale - 1])
                  ) * 1000000000
            if scale > 0:
                ts += (-1 if value[0] == u'-' else 1) * int(
                    value[-scale:] + zero_fill)
            return numpy.datetime64(ts, 'ns')

        return conv if scale > 0 else conv0

    def _get_session_tz(self):
        """ Get the session timezone or use the local computer's timezone. """
        try:
            return pytz.timezone(self.get_parameter(u'TIMEZONE'))
        except pytz.exceptions.UnknownTimeZoneError:
            self.logger.warn('converting to tzinfo failed')
            if tzlocal is not None:
                return tzlocal.get_localzone()
            else:
                try:
                    return datetime.timezone.utc
                except AttributeError:  # py2k
                    return pytz.timezone('UTC')

    def _pre_TIMESTAMP_LTZ_to_python(self, value, ctx):
        """
        TIMESTAMP LTZ to datetime

        This takes consideration of the session parameter TIMEZONE if
        available. If not, tzlocal is used
        """
        microseconds, is_negative, fraction_of_nanoseconds = \
            self._extract_timestamp(value, ctx)
        tzinfo_value = self._get_session_tz()

        try:
            t0 = ZERO_EPOCH + timedelta(seconds=(microseconds))
            t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo_value)
            return t, is_negative, fraction_of_nanoseconds
        except OverflowError:
            self.logger.debug(
                "OverflowError in converting from epoch time to "
                "timestamp_ltz: %s(ms). Falling back to use struct_time."
            )
            return time.gmtime(microseconds), is_negative, \
                   fraction_of_nanoseconds

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        tzinfo = self._get_session_tz()
        scale = ctx['scale']

        conv0 = lambda value: datetime.fromtimestamp(float(value), tz=tzinfo)

        def conv(value):
            microseconds = float(value[0:-scale + 6])
            return datetime.fromtimestamp(microseconds, tz=tzinfo)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_LTZ_numpy_to_python(self, ctx):
        tzinfo = self._get_session_tz()
        scale = ctx['scale']

        def conv(value):
            zero_fill = ctx['zero_fill']
            seconds = int(value[0:-scale - 1]) if scale > 0 else int(value)
            # construct datetime object to get utcoffset
            dt = ZERO_EPOCH + timedelta(seconds=seconds)
            offset = tzinfo.utcoffset(dt)
            if offset.days < 0:
                ts = (int(value[0:-scale - 1]) + (offset.seconds - 86400)
                      ) * 1000000000
            else:
                ts = (int(value[0:-scale - 1]) + offset.seconds
                      ) * 1000000000
            if scale > 0:
                ts += (-1 if value[0] == u'-' else 1) * int(
                    value[-scale:] + zero_fill)
            return numpy.datetime64(ts, 'ns')

        return conv

    _TIMESTAMP_to_python = _TIMESTAMP_LTZ_to_python

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """
        TIMESTAMP NTZ to datetime

        No timezone info is attached.
        """

        scale = ctx['scale']

        conv0 = lambda value: datetime.utcfromtimestamp(float(value))

        def conv(value):
            microseconds = float(value[0:-scale + 6])
            return datetime.utcfromtimestamp(microseconds)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_NTZ_numpy_to_python(self, ctx):
        """
        TIMESTAMP NTZ to datetime64

        No timezone info is attached.
        """

        scale = ctx['scale']

        def conv(value):
            nanoseconds = int(decimal.Decimal(value).scaleb(scale))
            return numpy.datetime64(nanoseconds, 'ns')

        return conv

    def _TIME_to_python(self, ctx):
        """
        TIME to formatted string, SnowflakeDateTime, or datetime.time

        No timezone is attached.
        """

        scale = ctx['scale']

        conv0 = lambda value: datetime.utcfromtimestamp(float(value)).time()

        def conv(value):
            microseconds = float(value[0:-scale + 6])
            return datetime.utcfromtimestamp(microseconds).time()

        return conv if scale > 6 else conv0

    def _VARIANT_to_python(self, _):
        return None  # skip conv

    _OBJECT_to_python = _VARIANT_to_python

    _ARRAY_to_python = _VARIANT_to_python

    def _BOOLEAN_to_python(self, ctx):
        return lambda value: value in (u'1', u'TRUE')

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

    def _nonetype_to_snowflake(self, _):
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
        tzinfo_value = SnowflakeConverter._generate_tzinfo_from_tzoffset(
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
        raise AttributeError('No method is available: {0}'.format(item))

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
