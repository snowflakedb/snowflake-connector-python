#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2016 Snowflake Computing Inc. All right reserved.
#
from datetime import datetime, timedelta
from logging import getLogger

import pytz
from . import errors
from .constants import UTF8
from .mixin import UnicodeMixin

ZERO_TIMEDELTA = timedelta(0)

ElementType = {
    u'Year2digit_ElementType': [u"YY", u"%y"],
    u'Year_ElementType': [u"YYYY", u"%Y"],
    u'Month_ElementType': [u"MM", u"%m"],
    u'MonthAbbrev_ElementType': [u"MON", u"%b"],
    u'DayOfMonth_ElementType': [u"DD", u"%d"],
    u'DayOfWeekAbbrev_ElementType': [u"DY", u"%a"],
    u'Hour24_ElementType': [u"HH24", u"%H"],
    u'Hour12_ElementType': [u"HH12", u"%I"],
    u'Hour_ElementType': [u"HH", u"%H"],
    u'Ante_Meridiem_ElementType': [u"AM", u"%p"],
    u'Post_Meridiem_ElementType': [u"PM", u"%p"],
    u'Minute_ElementType': [u"MI", u"%M"],
    u'Second_ElementType': [u"SS", u"%S"],
    u'MilliSecond_ElementType': [u"FF", u""],
    # special code for parsing fractions
    u'TZOffsetHourColonMin_ElementType': [u"TZH:TZM", u"%z"],
    u'TZOffsetHourMin_ElementType': [u"TZHTZM", u"%z"],
    u'TZOffsetHourOnly_ElementType': [u"TZH", u"%z"],
    u'TZAbbr_ElementType': [u"TZD", u"%Z"],
}


def sfdatetime_total_seconds_from_timedelta(td):
    return (td.microseconds + (
        td.seconds + td.days * 24 * 3600) * 10 ** 6) // 10 ** 6


def sfdatetime_to_snowflake(value):
    dt = value.datetime
    nanosecond = value.nanosecond

    tzinfo = dt.tzinfo
    if tzinfo:
        if pytz.utc != tzinfo:
            td = tzinfo.utcoffset(dt, is_dst=False)
        else:
            td = ZERO_TIMEDELTA
        sign = u'+' if td >= ZERO_TIMEDELTA else u'-'
        td_secs = sfdatetime_total_seconds_from_timedelta(td)
        h, m = divmod(abs(td_secs // 60), 60)
        if nanosecond:
            return (u'{year:d}-{month:02d}-{day:02d} '
                    u'{hour:02d}:{minute:02d}:{second:02d}.'
                    u'{nanosecond:09d}{sign}{tzh:02d}:{tzm:02d}').format(
                    year=dt.year, month=dt.month, day=dt.day,
                    hour=dt.hour, minute=dt.minute, second=dt.second,
                    nanosecond=nanosecond, sign=sign, tzh=h, tzm=m
            )
        return (
            u'{year:d}-{month:02d}-{day:02d} '
            u'{hour:02d}:{minute:02d}:{second:02d}'
            u'{sign}{tzh:02d}:{tzm:02d}').format(
                year=dt.year, month=dt.month, day=dt.day,
                hour=dt.hour, minute=dt.minute, second=dt.second, sign=sign,
                tzh=h,
                tzm=m
        )
    else:
        if nanosecond:
            return (
                u'{year:d}-{month:02d}-{day:02d} '
                u'{hour:02d}:{minute:02d}:{second:02d}.'
                u'{nanosecond:09d}').format(
                    year=dt.year, month=dt.month, day=dt.day,
                    hour=dt.hour, minute=dt.minute, second=dt.second,
                    nanosecond=nanosecond
            )
        return (
            u'{year:d}-{month:02d}-{day:02d} '
            u'{hour:02d}:{minute:02d}:{second:02d}').format(
                year=dt.year, month=dt.month, day=dt.day,
                hour=dt.hour, minute=dt.minute, second=dt.second
        )


class SnowflakeDateTime(UnicodeMixin):
    def __init__(self, ts, nanosecond):
        self._datetime = ts
        self._nanosecond = nanosecond

    @property
    def datetime(self):
        return self._datetime

    @property
    def nanosecond(self):
        return self._nanosecond

    def __repr__(self):
        return self.__str__()

    def __unicode__(self):
        return sfdatetime_to_snowflake(self)

    def __bytes__(self):
        return self.__unicode__().encode(UTF8)


class SnowflakeDateTimeFormat(object):
    def __init__(self, sql_format):
        self._sql_format = sql_format
        self._fragments = []
        self.logger = getLogger(__name__)

        self._compile()
        self._fraction_pos = -1
        if len(self._fragments) != 1:
            raise errors.InternalError(
                    u'Only one fragment is allowed {0}'.format(
                            u','.join(self._fragments)))

        self._simple_datetime_pattern = self._to_simple_datetime_pattern()

    def python_format(self):
        return self._python_format

    def format(self, value, scale=6):
        if self._fractions_pos >= 0:
            if self._fractions_len >= 0:
                scale = self._fractions_len
            if isinstance(value, datetime):
                nanos = value.microsecond
                nano_str = (u"{0:06d}".format(nanos))[:scale]
            else:
                nanos = value.nanosecond
                nano_str = (u"{0:09d}".format(nanos))[:scale]
            old_format = self._fragments[0][u'python_format']
            if self._fractions_with_dot:
                nano_str = u'.{0}'.format(nano_str)
            new_format = old_format[:self._fractions_pos] + nano_str + \
                         old_format[self._fractions_pos:]
        else:
            new_format = self._simple_datetime_pattern

        if isinstance(value, SnowflakeDateTime):
            if value.datetime.year < 1900:
                return value.datetime.isoformat()
            return value.datetime.strftime(new_format)
        else:
            if value.year < 1900:
                return value.isoformat()
            return value.strftime(new_format)

    def _to_simple_datetime_pattern(self):
        self.logger.debug(u"fragments: %s", self._fragments)
        if len(self._fragments) == 1:
            return self._fragments[0][u'python_format']
        else:
            return self._fragments[0][u'python_format'] + u"FFF" + \
                   self._fragments[1][u'python_format']

    def _create_new_fragment(self, element_types):
        self._fragments.append({
            u'python_format': self._python_format,
            u'element_types': element_types,
        })

    def _add_raw_char(self, sql_format, ch):
        sql_format += u'%%' if ch == u'%' else ch
        return sql_format

    def _add_element(self, element, element_types):
        self._python_format += element[1]  # python format
        element_types.append(element)
        return len(element[0])  # sql format

    def _compile(self):
        u"""Converts the date time/timestamp format to Python"""
        self._python_format = u""
        self._fractions_with_dot = False
        self._fractions_pre_formatter = None
        self._fractions_pos = -1
        self._fractions_len = -1

        element_types = []

        idx = 0
        u_sql_format = self._sql_format.upper()

        while idx < len(u_sql_format):
            ch = u_sql_format[idx]
            if ch == u'A':
                if u_sql_format[idx:].startswith(
                        ElementType[u'Ante_Meridiem_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Ante_Meridiem_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'D':
                if u_sql_format[idx:].startswith(
                        ElementType[u'DayOfMonth_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'DayOfMonth_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'DayOfWeekAbbrev_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'DayOfWeekAbbrev_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'H':
                if u_sql_format[idx:].startswith(
                        ElementType[u'Hour24_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Hour24_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'Hour12_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Hour12_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'Hour_ElementType'][0]):
                    idx += self._add_element(ElementType[u'Hour_ElementType'],
                                             element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'M':
                if u_sql_format[idx:].startswith(
                        ElementType[u'MonthAbbrev_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[
                                u'MonthAbbrev_ElementType'], element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'Month_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Month_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'Minute_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Minute_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'P':
                if u_sql_format[idx:].startswith(
                        ElementType[u'Post_Meridiem_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Post_Meridiem_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'S':
                if u_sql_format[idx:].startswith(
                        ElementType[u'Second_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Second_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'T':
                if u_sql_format[idx:].startswith(
                        ElementType[u'TZOffsetHourColonMin_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'TZOffsetHourColonMin_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'TZOffsetHourMin_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'TZOffsetHourMin_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'TZOffsetHourOnly_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'TZOffsetHourOnly_ElementType'],
                            element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'TZAbbr_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'TZAbbr_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'Y':
                if u_sql_format[idx:].startswith(
                        ElementType[u'Year_ElementType'][0]):
                    idx += self._add_element(ElementType[u'Year_ElementType'],
                                             element_types)
                elif u_sql_format[idx:].startswith(
                        ElementType[u'Year2digit_ElementType'][0]):
                    idx += self._add_element(
                            ElementType[u'Year2digit_ElementType'],
                            element_types)
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'.':
                if idx + 1 < len(u_sql_format) and \
                        u_sql_format[idx + 1:].startswith(
                                ElementType[u'MilliSecond_ElementType'][0]):
                    # Will be FF, just mark that there's a dot before FF
                    self._fractions_with_dot = True
                    idx += 1
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'F':
                if u_sql_format[idx:].startswith(
                        ElementType[u'MilliSecond_ElementType'][0]):
                    idx += len(ElementType[u'MilliSecond_ElementType'][0])
                    # @TODO Handle multiple occurrences?
                    # Construct formatter to find fractions position.
                    self._fractions_pre_formatter = self._python_format
                    self._fractions_pos = len(self._python_format)
                    self._fractions_len = -1
                    if idx < len(u_sql_format) and u_sql_format[idx].isdigit():
                        self._fractions_len = int(u_sql_format[idx])
                        idx += 1
                else:
                    self._python_format = self._add_raw_char(
                            self._python_format, ch)
                    idx += 1
            elif ch == u'"':
                # copy a double quoated string to the python format
                idx += 1
                while idx < len(self._sql_format) and \
                                self._sql_format[idx] != u'"':
                    self._python_format += self._sql_format[idx]
                    idx += 1
                if idx < len(self._sql_format):
                    idx += 1
            else:
                self._python_format = self._add_raw_char(self._python_format,
                                                         ch)
                idx += 1

        if len(element_types) > 0 or len(
                self._python_format) > 0 or self._fractions_len > 0:
            self._create_new_fragment(element_types)
