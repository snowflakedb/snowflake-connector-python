#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import binascii
import decimal
import time
from datetime import datetime, timedelta, date
from logging import getLogger

import pytz

from .compat import IS_BINARY, TO_UNICODE, IS_NUMERIC
from .errorcode import ER_NOT_SUPPORT_DATA_TYPE
from .errors import ProgrammingError
from .sfbinaryformat import binary_to_python, binary_to_snowflake
from .sfdatetime import sfdatetime_total_seconds_from_timedelta

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
ZERO_EPOCH_DATE = date(1970, 1, 1)
ZERO_EPOCH = datetime.utcfromtimestamp(0)
ZERO_FILL = u'000000000'

logger = getLogger(__name__)

PYTHON_TO_SNOWFLAKE_TYPE = {
    u'int': u'FIXED',
    u'long': u'FIXED',
    u'decimal': u'FIXED',
    u'float': u'REAL',
    u'str': u'TEXT',
    u'unicode': u'TEXT',
    u'bytes': u'BINARY',
    u'bytearray': u'BINARY',
    u'bool': u'BOOLEAN',
    u'bool_': u'BOOLEAN',
    u'nonetype': u'ANY',
    u'datetime': u'TIMESTAMP_NTZ',
    u'sfdatetime': u'TIMESTAMP_NTZ',
    u'date': u'DATE',
    u'time': u'TIME',
    u'struct_time': u'TIMESTAMP_NTZ',
    u'timedelta': u'TIME',
    u'list': u'TEXT',
    u'tuple': u'TEXT',
    u'int8': u'FIXED',
    u'int16': u'FIXED',
    u'int32': u'FIXED',
    u'int64': u'FIXED',
    u'uint8': u'FIXED',
    u'uint16': u'FIXED',
    u'uint32': u'FIXED',
    u'uint64': u'FIXED',
    u'float16': u'REAL',
    u'float32': u'REAL',
    u'float64': u'REAL',
    u'datetime64': u'TIMESTAMP_NTZ',
    u'quoted_name': u'TEXT',
}


def convert_datetime_to_epoch(dt):
    """
    Converts datetime to epoch time in seconds.
    If Python > 3.3, you may use timestamp() method
    """
    if dt.tzinfo is not None:
        dt0 = dt.astimezone(pytz.UTC).replace(tzinfo=None)
    else:
        dt0 = dt
    return (dt0 - ZERO_EPOCH).total_seconds()


def _convert_datetime_to_epoch_nanoseconds(dt):
    return u"{:f}".format(
        convert_datetime_to_epoch(dt)).replace(u'.', u'') + u'000'


def _convert_date_to_epoch_milliseconds(dt):
    return u'{:.3f}'.format(
        (dt - ZERO_EPOCH_DATE).total_seconds()).replace(u'.', u'')


def _convert_time_to_epoch_nanoseconds(tm):
    return TO_UNICODE(tm.hour * 3600 + tm.minute * 60 + tm.second) + \
           "{:06d}".format(tm.microsecond) + u'000'


def _extract_timestamp(value, ctx):
    """
    Extracts timestamp from a raw data
    """
    scale = ctx['scale']
    microseconds = float(
        value[0:-scale + 6]) if scale > 6 else float(value)
    fraction_of_nanoseconds = _adjust_fraction_of_nanoseconds(
        value, ctx['max_fraction'], scale)

    return microseconds, fraction_of_nanoseconds


def _adjust_fraction_of_nanoseconds(value, max_fraction, scale):
    if scale == 0:
        return 0
    if value[0] != '-':
        return int(value[-scale:] + ZERO_FILL[:9 - scale])

    frac = int(value[-scale:])
    if frac == 0:
        return 0
    else:
        return int(TO_UNICODE(max_fraction - frac) + ZERO_FILL[:9 - scale])


def _generate_tzinfo_from_tzoffset(tzoffset_minutes):
    """
    Generates tzinfo object from tzoffset.
    """
    return pytz.FixedOffset(tzoffset_minutes)


class SnowflakeConverter(object):
    def __init__(self, **kwargs):
        self._parameters = {}
        self._use_numpy = kwargs.get('use_numpy', False) and numpy is not None

        logger.debug('use_numpy: %s', self._use_numpy)

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

    #
    # FROM Snowflake to Python Objects
    #
    def to_python_method(self, type_name, column):
        ctx = column.copy()
        if ctx.get('scale') is not None:
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
        logger.warning(
            "No column converter found for type: %s", type_name)
        return None  # Skip conversion

    def _FIXED_to_python(self, ctx):
        return int if ctx['scale'] == 0 else decimal.Decimal

    def _FIXED_numpy_to_python(self, ctx):
        if ctx['scale']:
            return numpy.float64
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
            except (OSError, ValueError) as e:
                logger.debug("Failed to convert: %s", e)
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

    def _TIMESTAMP_TZ_to_python(self, ctx):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """

        scale = ctx['scale']

        def conv0(encoded_value):
            value, tz = encoded_value.split()
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            return datetime.fromtimestamp(float(value), tz=tzinfo)

        def conv(encoded_value):
            value, tz = encoded_value.split()
            microseconds = float(value[0:-scale + 6])
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            return datetime.fromtimestamp(microseconds, tz=tzinfo)

        return conv if scale > 6 else conv0

    def _get_session_tz(self):
        """ Get the session timezone or use the local computer's timezone. """
        try:
            tz = self.get_parameter(u'TIMEZONE')
            if not tz:
                tz = 'UTC'
            return pytz.timezone(tz)
        except pytz.exceptions.UnknownTimeZoneError:
            logger.warning('converting to tzinfo failed')
            if tzlocal is not None:
                return tzlocal.get_localzone()
            else:
                return datetime.timezone.utc

    def _pre_TIMESTAMP_LTZ_to_python(self, value, ctx):
        """
        TIMESTAMP LTZ to datetime

        This takes consideration of the session parameter TIMEZONE if
        available. If not, tzlocal is used
        """
        microseconds, fraction_of_nanoseconds = _extract_timestamp(value, ctx)
        tzinfo_value = self._get_session_tz()

        try:
            t0 = ZERO_EPOCH + timedelta(seconds=(microseconds))
            t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo_value)
            return t, fraction_of_nanoseconds
        except OverflowError:
            logger.debug(
                "OverflowError in converting from epoch time to "
                "timestamp_ltz: %s(ms). Falling back to use struct_time."
            )
            return time.localtime(microseconds), fraction_of_nanoseconds

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        tzinfo = self._get_session_tz()
        scale = ctx['scale']

        conv0 = lambda value: datetime.fromtimestamp(float(value), tz=tzinfo)

        def conv(value):
            microseconds = float(value[0:-scale + 6])
            return datetime.fromtimestamp(microseconds, tz=tzinfo)

        return conv if scale > 6 else conv0

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

        def conv(value):
            nanoseconds = int(decimal.Decimal(value).scaleb(9))
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

    def snowflake_type(self, value):
        """
        Returns Snowflake data type for the value. This is used for qmark
        parameter style
        """
        type_name = value.__class__.__name__.lower()
        return PYTHON_TO_SNOWFLAKE_TYPE.get(type_name)

    def to_snowflake_bindings(self, snowflake_type, value):
        """
        Converts Python data to snowflake data for qmark and numeric
        parameter style

        The output is bound in a query in the server side.
        """
        type_name = value.__class__.__name__.lower()
        return getattr(self, u"_{type_name}_to_snowflake_bindings".format(
            type_name=type_name))(snowflake_type, value)

    def _str_to_snowflake_bindings(self, _, value):
        # NOTE: str type is always taken as a text data and never binary
        return TO_UNICODE(value)

    _int_to_snowflake_bindings = _str_to_snowflake_bindings
    _long_to_snowflake_bindings = _str_to_snowflake_bindings
    _float_to_snowflake_bindings = _str_to_snowflake_bindings
    _unicode_to_snowflake_bindings = _str_to_snowflake_bindings
    _decimal_to_snowflake_bindings = _str_to_snowflake_bindings

    def _bytes_to_snowflake_bindings(self, _, value):
        return binascii.hexlify(value).decode(u'utf-8')

    _bytearray_to_snowflake_bindings = _bytes_to_snowflake_bindings

    def _bool_to_snowflake_bindings(self, _, value):
        return TO_UNICODE(value).lower()

    def _nonetype_to_snowflake_bindings(self, *_):
        return None

    def _date_to_snowflake_bindings(self, _, value):
        # milliseconds
        return _convert_date_to_epoch_milliseconds(value)

    def _time_to_snowflake_bindings(self, _, value):
        # nanoseconds
        return _convert_time_to_epoch_nanoseconds(value)

    def _datetime_to_snowflake_bindings(self, snowflake_type, value):
        snowflake_type = snowflake_type.upper()
        if snowflake_type == 'TIMESTAMP_LTZ':
            _, t = self._derive_offset_timestamp(value)
            return _convert_datetime_to_epoch_nanoseconds(t)
        elif snowflake_type == 'TIMESTAMP_NTZ':
            # nanoseconds
            return _convert_datetime_to_epoch_nanoseconds(value)
        elif snowflake_type == 'TIMESTAMP_TZ':
            offset, t = self._derive_offset_timestamp(value, is_utc=True)
            return _convert_datetime_to_epoch_nanoseconds(t) + \
                   u' {:04d}'.format(int(offset))
        else:
            raise ProgrammingError(
                msg=u'Binding datetime object with Snowflake data type {} is '
                    u'not supported.'.format(snowflake_type),
                errno=ER_NOT_SUPPORT_DATA_TYPE)

    def _derive_offset_timestamp(self, value, is_utc=False):
        """
        Derives TZ offset and timestamp from the datatime object
        """
        tzinfo = value.tzinfo
        if tzinfo is None:
            # If no tzinfo is attached, use local timezone.
            tzinfo = self._get_session_tz() if not is_utc else pytz.UTC
            t = pytz.utc.localize(value, is_dst=False).astimezone(tzinfo)
        else:
            # if tzinfo is attached, just covert to epoch time
            # as the server expects it in UTC anyway
            t = value
        offset = tzinfo.utcoffset(
            t.replace(tzinfo=None)).total_seconds() / 60 + 1440
        return offset, t

    def _struct_time_to_snowflake_bindings(self, snowflake_type, value):
        return self._datetime_to_snowflake_bindings(
            snowflake_type,
            datetime.fromtimestamp(time.mktime(value)))

    def _timedelta_to_snowflake_bindings(self, snowflake_type, value):
        snowflake_type = snowflake_type.upper()
        if snowflake_type != u'TIME':
            raise ProgrammingError(
                msg=u'Binding timedelta object with Snowflake data type {} is '
                    u'not supported.'.format(snowflake_type),
                errno=ER_NOT_SUPPORT_DATA_TYPE)
        (hours, r) = divmod(value.seconds, 3600)
        (mins, secs) = divmod(r, 60)
        hours += value.days * 24
        return TO_UNICODE(hours * 3600 + mins * 60 + secs) + \
               "{:06d}".format(value.microseconds) + u'000'

    def to_snowflake(self, value):
        """
        Converts Python data to Snowflake data for pyformat/format style.

        The output is bound in a query in the client side.
        """
        type_name = value.__class__.__name__.lower()
        return getattr(self, u"_{type_name}_to_snowflake".format(
            type_name=type_name))(value)

    def _int_to_snowflake(self, value):
        return int(value)

    def _long_to_snowflake(self, value):
        return long(value)  # noqa: F821

    def _float_to_snowflake(self, value):
        return float(value)

    def _str_to_snowflake(self, value):
        return TO_UNICODE(value)

    _unicode_to_snowflake = _str_to_snowflake

    def _bytes_to_snowflake(self, value):
        return binary_to_snowflake(value)

    _bytearray_to_snowflake = _bytes_to_snowflake

    def _bool_to_snowflake(self, value):
        return value

    def _bool__to_snowflake(self, value):
        return bool(value)

    def _nonetype_to_snowflake(self, _):
        return None

    def _total_seconds_from_timedelta(self, td):
        return sfdatetime_total_seconds_from_timedelta(td)

    def _datetime_to_snowflake(self, value):
        tzinfo_value = value.tzinfo
        if tzinfo_value:
            if pytz.utc != tzinfo_value:
                try:
                    td = tzinfo_value.utcoffset(value)
                except pytz.exceptions.AmbiguousTimeError:
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

    def date_to_snowflake(self, value):
        """
        Converts Date object to Snowflake object
        """
        return self._date_to_snowflake(value)

    def _date_to_snowflake(self, value):
        return u'{year:d}-{month:02d}-{day:02d}'.format(
            year=value.year, month=value.month, day=value.day)

    def _time_to_snowflake(self, value):
        if value.microsecond:
            return value.strftime(u'%H:%M:%S.%%06d') % value.microsecond
        return value.strftime(u'%H:%M:%S')

    def _struct_time_to_snowflake(self, value):
        tzinfo_value = _generate_tzinfo_from_tzoffset(time.timezone // 60)
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
        return TO_UNICODE(value) + u'+00:00'

    def _quoted_name_to_snowflake(self, value):
        return TO_UNICODE(value)

    def __getattr__(self, item):
        if item.endswith('_to_snowflake'):
            raise ProgrammingError(
                msg=u"Binding data in type ({}) is not supported.".format(
                    item[1:item.find('_to_snowflake')]),
                errno=ER_NOT_SUPPORT_DATA_TYPE
            )
        elif item.endswith('to_snowflake_bindings'):
            raise ProgrammingError(
                msg=u"Binding data in type ({}) is not supported.".format(
                    item[1:item.find('_to_snowflake_bindings')]),
                errno=ER_NOT_SUPPORT_DATA_TYPE
            )
        raise AttributeError('No method is available: {}'.format(item))

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
            return u"X'{}'".format(value.decode('ascii'))

        return u"'{}'".format(value)
