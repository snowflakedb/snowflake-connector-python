#!/usr/bin/env python
from __future__ import annotations

import logging
import os
import unittest.mock

import pytest

import snowflake.connector
from snowflake.connector.errors import OperationalError


def test_set_proxies():
    from snowflake.connector.proxy import set_proxies

    assert set_proxies("proxyhost", "8080") == {
        "http": "http://proxyhost:8080",
        "https": "http://proxyhost:8080",
    }
    assert set_proxies("http://proxyhost", "8080") == {
        "http": "http://proxyhost:8080",
        "https": "http://proxyhost:8080",
    }
    assert set_proxies("http://proxyhost", "8080", "testuser", "testpass") == {
        "http": "http://testuser:testpass@proxyhost:8080",
        "https": "http://testuser:testpass@proxyhost:8080",
    }
    assert set_proxies("proxyhost", "8080", "testuser", "testpass") == {
        "http": "http://testuser:testpass@proxyhost:8080",
        "https": "http://testuser:testpass@proxyhost:8080",
    }

    # NOTE environment variable is set if the proxy parameter is specified.
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]


@pytest.mark.skipolddriver
def test_socks_5_proxy_missing_proxy_header_attribute(caplog):
    from snowflake.connector.vendored.urllib3.poolmanager import ProxyManager

    os.environ["HTTPS_PROXY"] = "socks5://localhost:8080"

    class MockSOCKSProxyManager:
        def __init__(self):
            pass

        def connection_from_url(self, url):
            pass

    def mock_proxy_manager_for_url_no_header(*args, **kwargs):
        return MockSOCKSProxyManager()

    def mock_proxy_manager_for_url_wiht_header(*args, **kwargs):
        return ProxyManager("testurl")

    # connection
    caplog.set_level(logging.DEBUG, "snowflake.connector")

    # bad path
    with unittest.mock.patch(
        "snowflake.connector.network.ProxySupportAdapter.proxy_manager_for",
        mock_proxy_manager_for_url_no_header,
    ):
        with pytest.raises(OperationalError):
            snowflake.connector.connect(
                account="testaccount",
                user="testuser",
                password="testpassword",
                database="TESTDB",
                warehouse="TESTWH",
            )
    assert "Unable to set 'Host' to proxy manager of type" in caplog.text

    caplog.clear()

    # happy path
    with unittest.mock.patch(
        "snowflake.connector.network.ProxySupportAdapter.proxy_manager_for",
        mock_proxy_manager_for_url_wiht_header,
    ):
        with pytest.raises(OperationalError):
            snowflake.connector.connect(
                account="testaccount",
                user="testuser",
                password="testpassword",
                database="TESTDB",
                warehouse="TESTWH",
            )
    assert "Unable to set 'Host' to proxy manager of type" not in caplog.text

    del os.environ["HTTPS_PROXY"]
