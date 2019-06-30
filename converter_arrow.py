#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger
from decimal import Context
from datetime import datetime, timedelta, date
from .converter import SnowflakeConverter

logger = getLogger(__name__)

ZERO_EPOCH = datetime.utcfromtimestamp(0)


class SnowflakeArrowConverter(SnowflakeConverter):
    """
    Convert from arrow data into python native data types
    """

    def to_python_method(self, type_name, column):
        ctx = column.copy()

        if type_name == 'FIXED' and ctx['scale'] != 0:
            ctx['decimalCtx'] = Context(prec=ctx['precision'])

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
        if ctx['scale'] == 0:
            return lambda x: x.as_py()
        else:
            return lambda x, decimal_ctx=ctx['decimalCtx']: decimal_ctx.create_decimal(x.as_py())

    def _REAL_to_python(self, _):
        return lambda x: x.as_py()

    def _TEXT_to_python(self, _):
        return lambda x: x.as_py()

    def _BINARY_to_python(self, _):
        return lambda x: x.as_py()

    def _VARIANT_to_python(self, _):
        return lambda x: x.as_py()

    def _BOOLEAN_to_python(self, _):
        return lambda x: x.as_py() > 0

    def _DATE_to_python(self, _):

        def conv(value):
            try:
                return datetime.utcfromtimestamp(value * 86400).date()
            except OSError as e:
                logger.debug("Failed to convert: %s", e)
                ts = ZERO_EPOCH + timedelta(
                    seconds=value * (24 * 60 * 60))
                return date(ts.year, ts.month, ts.day)

        return conv
