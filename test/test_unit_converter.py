#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger

from snowflake.connector.compat import (PY_ISSUE_23517, TO_UNICODE)
from snowflake.connector.converter import SnowflakeConverter
from snowflake.connector.converter_issue23517 import (
    SnowflakeConverterIssue23517)
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL

logger = getLogger(__name__)

Converter = SnowflakeConverter if not PY_ISSUE_23517 else \
    SnowflakeConverterIssue23517

ConverterSnowSQL = SnowflakeConverterSnowSQL


def test_is_dst():
    """
    SNOW-6020: Failed to convert to local time during DST is being
    changed
    """
    # DST to non-DST
    conv = Converter()
    conv.set_parameter('TIMEZONE', 'America/Los_Angeles')

    col_meta = {
        'name': 'CREATED_ON',
        'type': 6,
        'length': None,
        'precision': None,
        'scale': 3,
        'nullable': True,
    }
    m = conv.to_python_method('TIMESTAMP_LTZ', col_meta)
    ret = m('1414890189.000')

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
    m = conv.to_python_method('TIMESTAMP_LTZ', col_meta)
    ret = m('1425780189.000')

    assert TO_UNICODE(ret) == u'2015-03-07 18:03:09-08:00', \
        'Timestamp during from non-DST to DST'


def test_more_timestamps():
    col_meta_3 = {
        'scale': 9
    }

    conv = ConverterSnowSQL()
    conv.set_parameter('TIMESTAMP_NTZ_OUTPUT_FORMAT',
                       'YYYY-MM-DD HH24:MI:SS.FF9')
    m = conv.to_python_method('TIMESTAMP_NTZ', col_meta_3)
    ret = m('-2208943503.876543211')
    assert ret == '1900-01-01 12:34:56.123456789'
