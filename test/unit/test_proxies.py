#!/usr/bin/env python
from __future__ import annotations

import logging
import os
import unittest.mock

import pytest

import snowflake.connector
from snowflake.connector.errors import OperationalError


@pytest.fixture
def preserve_proxy_envs():
    """Fixture to preserve and restore proxy environment variables"""
    original_http_proxy = os.environ.get("HTTP_PROXY")
    original_https_proxy = os.environ.get("HTTPS_PROXY")

    try:
        yield
    finally:
        # Restore original proxy environment variables
        if original_http_proxy is not None:
            os.environ["HTTP_PROXY"] = original_http_proxy
        elif "HTTP_PROXY" in os.environ:
            del os.environ["HTTP_PROXY"]

        if original_https_proxy is not None:
            os.environ["HTTPS_PROXY"] = original_https_proxy
        elif "HTTPS_PROXY" in os.environ:
            del os.environ["HTTPS_PROXY"]


def test_set_proxies(preserve_proxy_envs):
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


@pytest.mark.skipolddriver
def test_socks_5_proxy_missing_proxy_header_attribute(caplog, preserve_proxy_envs):
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
