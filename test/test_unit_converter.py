#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger

from snowflake.connector.compat import TO_UNICODE
from snowflake.connector.converter import SnowflakeConverter

logger = getLogger(__name__)


def test_is_dst():
    """
    SNOW-6020: Failed to convert to local time during DST is being
    changed
    """
    conv = SnowflakeConverter()
    conv.set_parameter('TIMEZONE', 'America/Los_Angeles')

    # DST to non-DST

    col_meta = {
        'name': 'CREATED_ON',
        'type': 6,
        'length': None,
        'precision': None,
        'scale': 3,
        'nullable': True,
    }
    m = conv.to_python_method('TIMESTAMP_LTZ', col_meta, 0)
    ret = m(1414890189)

    assert TO_UNICODE(ret) == u'2014-11-01 18:03:09-07:00', \
        'Timestamp during from DST to non-DST'

    # non-DST to DST
    col_meta = {
        'name': 'CREATED_ON',
        'type': 6,
        'length': None,
        'precision': None,
        'scale': 3,
        'nullable': True,
    }
    m = conv.to_python_method('TIMESTAMP_LTZ', col_meta, 0)
    ret = m(1425780189)

    assert TO_UNICODE(ret) == u'2015-03-07 18:03:09-08:00', \
        'Timestamp during from non-DST to DST'
