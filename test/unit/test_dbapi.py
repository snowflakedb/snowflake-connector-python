#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector.dbapi import Binary


def test_Binary():
    assert Binary(b'foo') == b'foo'
