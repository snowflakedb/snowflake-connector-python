#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
from datetime import timedelta
from logging import getLogger

import pytz

from .converter import (SnowflakeConverter, ZERO_EPOCH)

logger = getLogger(__name__)


class SnowflakeConverterIssue23517(SnowflakeConverter):
    """
    Converter for Python 3.4.3 and 3.5.0
    This is to address http://bugs.python.org/issue23517
    """

    def __init__(self, **kwargs):
        super(SnowflakeConverterIssue23517, self).__init__(**kwargs)
        logger.info('initialized')

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
            microseconds = float(value)
            t = ZERO_EPOCH + timedelta(seconds=microseconds)
            if pytz.utc != tzinfo:
                t += tzinfo.utcoffset(t, is_dst=False)
            return t.replace(tzinfo=tzinfo)

        def conv(encoded_value):
            value, tz = encoded_value.split()
            tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(
                int(tz) - 1440)
            microseconds = float(value[0:-scale + 6])
            t = ZERO_EPOCH + timedelta(seconds=microseconds)
            if pytz.utc != tzinfo:
                t += tzinfo.utcoffset(t, is_dst=False)
            return t.replace(tzinfo=tzinfo)

        return conv if scale > 6 else conv0

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """
        TIMESTAMP NTZ to datetime

        No timezone info is attached.
        """

        scale = ctx['scale']

        def conv0(value):
            logger.debug('timestamp_ntz: %s', value)
            return ZERO_EPOCH + timedelta(seconds=(float(value)))

        def conv(value):
            logger.debug('timestamp_ntz: %s', value)
            microseconds = float(value[0:-scale + 6])
            return ZERO_EPOCH + timedelta(seconds=(microseconds))

        return conv if scale > 6 else conv0

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        def conv(value):
            t, _, _ = self._pre_TIMESTAMP_LTZ_to_python(value, ctx)
            return t

        return conv

    def _TIME_to_python(self, ctx):
        """
        TIME to formatted string, SnowflakeDateTime, or datetime.time

        No timezone is attached.
        """

        scale = ctx['scale']

        conv0 = lambda value: (
            ZERO_EPOCH + timedelta(seconds=(float(value)))).time()

        def conv(value):
            microseconds = float(value[0:-scale + 6])
            return (ZERO_EPOCH + timedelta(seconds=(microseconds))).time()

        return conv if scale > 6 else conv0
