#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.util_text import construct_hostname


def test_construct_hostname_basic():
    assert construct_hostname('eu-central-1', 'account1') == \
           'account1.eu-central-1.snowflakecomputing.com'

    assert construct_hostname('', 'account1') == \
           'account1.snowflakecomputing.com'

    assert construct_hostname(None, 'account1') == \
           'account1.snowflakecomputing.com'

    assert construct_hostname('as-east-3', 'account1') == \
           'account1.as-east-3.snowflakecomputing.com'

    assert construct_hostname('as-east-3', 'account1.eu-central-1') == \
           'account1.as-east-3.snowflakecomputing.com'

    assert construct_hostname('', 'account1.eu-central-1') == \
           'account1.eu-central-1.snowflakecomputing.com'

    assert construct_hostname(None, 'account1.eu-central-1') == \
           'account1.eu-central-1.snowflakecomputing.com'

    assert construct_hostname(None, 'account1-jkabfvdjisoa778wqfgeruishafeuw89q.global') == \
           'account1-jkabfvdjisoa778wqfgeruishafeuw89q.global.snowflakecomputing.com'
