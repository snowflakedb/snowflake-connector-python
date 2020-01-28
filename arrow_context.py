#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import decimal
import time
from datetime import datetime, timedelta
from logging import getLogger

import pytz

from .constants import PARAMETER_TIMEZONE
from .converter import _generate_tzinfo_from_tzoffset

try:
    import numpy
except ImportError:
    numpy = None


try:
    import tzlocal
except ImportError:
    tzlocal = None

ZERO_EPOCH = datetime.utcfromtimestamp(0)

logger = getLogger(__name__)


class ArrowConverterContext(object):
    def __init__(self, session_parameters=None):
        if session_parameters is None:
            session_parameters = {}
        self._timezone = None if PARAMETER_TIMEZONE not in session_parameters else session_parameters[PARAMETER_TIMEZONE]

    @property
    def timezone(self):
        return self._timezone

    @timezone.setter
    def timezone(self, tz):
        self._timezone = tz

    def _get_session_tz(self):
        """ Get the session timezone or use the local computer's timezone. """
        try:
            tz = 'UTC' if not self.timezone else self.timezone
            return pytz.timezone(tz)
        except pytz.exceptions.UnknownTimeZoneError:
            logger.warning('converting to tzinfo failed')
            if tzlocal is not None:
                return tzlocal.get_localzone()
            else:
                try:
                    return datetime.timezone.utc
                except AttributeError:
                    return pytz.timezone('UTC')

    def TIMESTAMP_TZ_to_python(self, microseconds, tz):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked

        @para microseconds : float
        @para tz : int
        """

        tzinfo = _generate_tzinfo_from_tzoffset(tz - 1440)
        return datetime.fromtimestamp(microseconds, tz=tzinfo)

    def TIMESTAMP_TZ_to_python_windows(self, microseconds, tz):
        tzinfo = _generate_tzinfo_from_tzoffset(tz - 1440)
        t = ZERO_EPOCH + timedelta(seconds=microseconds)
        if pytz.utc != tzinfo:
            t += tzinfo.utcoffset(t)
        return t.replace(tzinfo=tzinfo)

    def TIMESTAMP_NTZ_to_python(self, microseconds):
        return datetime.utcfromtimestamp(microseconds)

    def TIMESTAMP_NTZ_to_python_windows(self, microseconds):
        return ZERO_EPOCH + timedelta(seconds=microseconds)

    def TIMESTAMP_LTZ_to_python(self, microseconds):
        tzinfo = self._get_session_tz()
        return datetime.fromtimestamp(microseconds, tz=tzinfo)

    def TIMESTAMP_LTZ_to_python_windows(self, microseconds):
        tzinfo = self._get_session_tz()
        try:
            t0 = ZERO_EPOCH + timedelta(seconds=microseconds)
            t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo)
            return t
        except OverflowError:
            logger.debug(
                "OverflowError in converting from epoch time to "
                "timestamp_ltz: %s(ms). Falling back to use struct_time."
            )
            return time.localtime(microseconds)

    def REAL_to_numpy_float64(self, py_double):
        return numpy.float64(py_double)

    def FIXED_to_numpy_int64(self, py_long):
        return numpy.int64(py_long)

    def FIXED_to_numpy_float64(self, py_long, scale):
        return numpy.float64(decimal.Decimal(py_long).scaleb(-scale))

    def DATE_to_numpy_datetime64(self, py_days):
        return numpy.datetime64(py_days, 'D')

    def TIMESTAMP_NTZ_ONE_FIELD_to_numpy_datetime64(self, value, scale):
        nanoseconds = int(decimal.Decimal(value).scaleb(9 - scale))
        return numpy.datetime64(nanoseconds, 'ns')

    def TIMESTAMP_NTZ_TWO_FIELD_to_numpy_datetime64(self, epoch, fraction):
        nanoseconds = int(decimal.Decimal(epoch).scaleb(9) + decimal.Decimal(fraction))
        return numpy.datetime64(nanoseconds, 'ns')
