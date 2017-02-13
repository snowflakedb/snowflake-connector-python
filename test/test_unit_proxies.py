# encoding=utf-8
# !/usr/bin/env python
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#


def test_set_proxies():
    from snowflake.connector.ssl_wrap_socket import set_proxies

    assert set_proxies('proxyhost', '8080') == {
        'http': 'http://proxyhost:8080',
        'https': 'http://proxyhost:8080',
    }
    assert set_proxies('http://proxyhost', '8080') == {
        'http': 'http://proxyhost:8080',
        'https': 'http://proxyhost:8080',
    }
    assert set_proxies('http://proxyhost', '8080', 'testuser', 'testpass') == {
        'http': 'http://testuser:testpass@proxyhost:8080',
        'https': 'http://testuser:testpass@proxyhost:8080',
    }
    assert set_proxies('proxyhost', '8080', 'testuser', 'testpass') == {
        'http': 'http://testuser:testpass@proxyhost:8080',
        'https': 'http://testuser:testpass@proxyhost:8080',
    }
