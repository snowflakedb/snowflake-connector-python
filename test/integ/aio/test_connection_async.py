#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations


async def test_basic(conn_testaccount):
    """Basic Connection test."""
    assert conn_testaccount, "invalid cnx"
    # Test default values
    assert conn_testaccount.session_id
