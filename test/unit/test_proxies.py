#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations


def test_get_proxy_url():
    from snowflake.connector.proxy import get_proxy_url

    assert get_proxy_url("host", "port", "user", "password") == (
        "http://user:password@host:port"
    )
    assert get_proxy_url("host", "port") == "http://host:port"

    assert get_proxy_url("http://host", "port") == "http://host:port"

    assert get_proxy_url("https://host", "port", "user", "password") == (
        "http://user:password@host:port"
    )
