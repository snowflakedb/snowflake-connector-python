#!/usr/bin/env python
from __future__ import annotations

from snowflake.connector.dbapi import Binary


def test_Binary():
    assert Binary(b"foo") == b"foo"
