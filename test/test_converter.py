#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger

from snowflake.connector import converter
from snowflake.connector.compat import TO_UNICODE

logger = getLogger(__name__)


def test_is_dst():
    """
    SNOW-6020: Failed to convert to local time during DST is being
    changed
    """
    conv = converter.SnowflakeConverter()
    conv.set_parameter('TIMEZONE', 'America/Los_Angeles')

    # DST to non-DST

    col_meta = ('created_on', 6, None, None, 0, 3, True)
    m, fmt = conv.to_python_method('TIMESTAMP_LTZ', col_meta)
    ret = m(1414890189, col_meta)

    # ret = conv.to_python(('created_on', 6, None, None, 0, 3, True),
    #                     1414890189)
    logger.debug(ret)
    assert TO_UNICODE(ret) == u'2014-11-01 18:03:09-07:00', \
        'Timestamp during from DST to non-DST'

    # non-DST to DST
    col_meta = ('created_on', 6, None, None, 0, 3, True)
    m, fmt = conv.to_python_method('TIMESTAMP_LTZ', col_meta)
    ret = m(1425780189, col_meta)

    logger.debug(ret)
    assert TO_UNICODE(ret) == u'2015-03-07 18:03:09-08:00', \
        'Timestamp during from non-DST to DST'
