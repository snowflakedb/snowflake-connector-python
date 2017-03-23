#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
from datetime import timedelta
from logging import getLogger

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

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """
        TIMESTAMP NTZ to datetime

        No timezone info is attached.
        """

        def conv(value):
            scale = ctx['scale']
            microseconds = float(
                value[0:-scale + 6]) if scale > 6 else float(value)
            t = ZERO_EPOCH + timedelta(seconds=(microseconds))
            return t

        return conv

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        def conv(value):
            t, _ = self._pre_TIMESTAMP_LTZ_to_python(value, ctx)
            return t

        return conv

    def _TIME_to_python(self, ctx):
        """
        TIME to formatted string, SnowflakeDateTime, or datetime.time

        No timezone is attached.
        """

        def conv(value):
            scale = ctx['scale']
            microseconds = float(
                value[0:-scale + 6]) if scale > 6 else float(value)
            return (ZERO_EPOCH + timedelta(seconds=(microseconds))).time()

        return conv
