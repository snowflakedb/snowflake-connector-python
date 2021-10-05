#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from datetime import datetime, time, timedelta
from logging import getLogger

import pytz

from .converter import ZERO_EPOCH, SnowflakeConverter, _generate_tzinfo_from_tzoffset

logger = getLogger(__name__)


class SnowflakeConverterIssue23517(SnowflakeConverter):
    """Converter for Python 3.5.0 or Any Python on Windows.

    This is to address http://bugs.python.org/issue23517
    """

    def __init__(self, **kwargs):
        super(SnowflakeConverterIssue23517, self).__init__(**kwargs)
        logger.debug("initialized")

    def _TIMESTAMP_TZ_to_python(self, ctx):
        """Converts TIMESTAMP TZ to datetime.

        The timezone offset is piggybacked.
        """
        scale = ctx["scale"]

        def conv0(encoded_value: str) -> datetime:
            value, tz = encoded_value.split()
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            microseconds = float(value)
            t = ZERO_EPOCH + timedelta(seconds=microseconds)
            if pytz.utc != tzinfo:
                t += tzinfo.utcoffset(t)
            return t.replace(tzinfo=tzinfo)

        def conv(encoded_value: str) -> datetime:
            value, tz = encoded_value.split()
            tzinfo = _generate_tzinfo_from_tzoffset(int(tz) - 1440)
            microseconds = float(value[0 : -scale + 6])
            t = ZERO_EPOCH + timedelta(seconds=microseconds)
            if pytz.utc != tzinfo:
                t += tzinfo.utcoffset(t)
            return t.replace(tzinfo=tzinfo)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """Converts TIMESTAMP NTZ to datetime.

        No timezone info is attached.
        """
        scale = ctx["scale"]

        def conv0(value: str) -> datetime:
            logger.debug("timestamp_ntz: %s", value)
            return ZERO_EPOCH + timedelta(seconds=(float(value)))

        def conv(value: str) -> datetime:
            logger.debug("timestamp_ntz: %s", value)
            microseconds = float(value[0 : -scale + 6])
            return ZERO_EPOCH + timedelta(seconds=(microseconds))

        return conv if scale > 6 else conv0

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        def conv(value: str) -> datetime:
            t, _ = self._pre_TIMESTAMP_LTZ_to_python(value, ctx)
            return t

        return conv

    def _TIME_to_python(self, ctx):
        """Converts TIME to formatted string, SnowflakeDateTime, or datetime.time.

        No timezone is attached.
        """
        scale = ctx["scale"]

        def conv0(value: str) -> time:
            return (ZERO_EPOCH + timedelta(seconds=(float(value)))).time()

        def conv(value: str) -> time:
            microseconds = float(value[0 : -scale + 6])
            return (ZERO_EPOCH + timedelta(seconds=(microseconds))).time()

        return conv if scale > 6 else conv0
