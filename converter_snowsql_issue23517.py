#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import time
from datetime import timedelta
from logging import getLogger

from .converter import (ZERO_EPOCH)
from .converter_snowsql import (format_sftimestamp, SnowflakeConverterSnowSQL)

logger = getLogger(__name__)


class SnowflakeConverterSnowSQLIssue23517(SnowflakeConverterSnowSQL):
    def __init__(self, **_):
        super(SnowflakeConverterSnowSQLIssue23517, self).__init__()
        logger.info('initialized')

    def _TIMESTAMP_TZ_to_python(self, ctx):
        """
        TIMESTAMP TZ to datetime

        The timezone offset is piggybacked.
        """

        def conv(value):
            t, fraction_of_nanoseconds = self._pre_TIMESTAMP_TZ_to_python(
                value, ctx)
            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_LTZ_to_python(self, ctx):
        def conv(value):
            t, fraction_of_nanoseconds = self._pre_TIMESTAMP_LTZ_to_python(
                value, ctx)
            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv

    def _TIMESTAMP_NTZ_to_python(self, ctx):
        """
        TIMESTAMP NTZ to Snowflake Formatted String

        No timezone info is attached.
        """

        def conv(value):
            microseconds, fraction_of_nanoseconds = self._extract_timestamp(
                value, ctx)
            try:
                t = ZERO_EPOCH + timedelta(seconds=(microseconds))
            except OverflowError:
                self.logger.debug(
                    "OverflowError in converting from epoch time to datetime: "
                    "%s(ms). Falling back to use struct_time.",
                    microseconds)
                t = time.gmtime(microseconds)
            return format_sftimestamp(ctx['fmt'], t, fraction_of_nanoseconds)

        return conv

    _TIME_to_python = _TIMESTAMP_NTZ_to_python
