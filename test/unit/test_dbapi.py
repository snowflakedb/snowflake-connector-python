#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from snowflake.connector.dbapi import Binary


def test_Binary():
    assert Binary(b"foo") == b"foo"
