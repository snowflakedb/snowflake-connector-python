#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import time
from datetime import datetime, timedelta
from logging import getLogger
from .constants import (
    PARAMETER_TIMEZONE)
from .converter import (
    _generate_tzinfo_from_tzoffset)

import pytz

try:
    import tzlocal
except ImportError:
    tzlocal = None

ZERO_EPOCH = datetime.utcfromtimestamp(0)

logger = getLogger(__name__)


class ArrowConverterContext(object):
    def __init__(self, session_parameters={}):
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
        return ZERO_EPOCH + timedelta(seconds=(microseconds))

    def TIMESTAMP_LTZ_to_python(self, microseconds):
        tzinfo = self._get_session_tz()
        return datetime.fromtimestamp(microseconds, tz=tzinfo)

    def TIMESTAMP_LTZ_to_python_windows(self, microseconds):
        tzinfo = self._get_session_tz()
        try:
            t0 = ZERO_EPOCH + timedelta(seconds=(microseconds))
            t = pytz.utc.localize(t0, is_dst=False).astimezone(tzinfo)
            return t
        except OverflowError:
            logger.debug(
                "OverflowError in converting from epoch time to "
                "timestamp_ltz: %s(ms). Falling back to use struct_time."
            )
            return time.localtime(microseconds)
