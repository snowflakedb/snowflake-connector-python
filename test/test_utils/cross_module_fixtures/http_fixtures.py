import os

import pytest

from snowflake.connector.compat import urlparse as compat_urlparse
from snowflake.connector.session_manager import SessionManager


@pytest.fixture
def proxy_env_vars():
    """Manages HTTP_PROXY and HTTPS_PROXY environment variables for testing."""
    original_http_proxy = os.environ.get("HTTP_PROXY")
    original_https_proxy = os.environ.get("HTTPS_PROXY")
    original_no_proxy = os.environ.get("NO_PROXY")

    def set_proxy_env_vars(proxy_url: str):
        """Set both HTTP_PROXY and HTTPS_PROXY to the given URL."""
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url

    def clear_proxy_env_vars():
        """Clear proxy environment variables."""
        if "HTTP_PROXY" in os.environ:
            del os.environ["HTTP_PROXY"]
        if "HTTPS_PROXY" in os.environ:
            del os.environ["HTTPS_PROXY"]
        if "NO_PROXY" in os.environ:
            del os.environ["NO_PROXY"]

    # Yield the helper functions
    yield set_proxy_env_vars, clear_proxy_env_vars

    # Cleanup: restore original values
    if original_http_proxy is not None:
        os.environ["HTTP_PROXY"] = original_http_proxy
    elif "HTTP_PROXY" in os.environ:
        del os.environ["HTTP_PROXY"]

    if original_https_proxy is not None:
        os.environ["HTTPS_PROXY"] = original_https_proxy
    elif "HTTPS_PROXY" in os.environ:
        del os.environ["HTTPS_PROXY"]

    if original_no_proxy is not None:
        os.environ["NO_PROXY"] = original_no_proxy
    elif "NO_PROXY" in os.environ:
        del os.environ["NO_PROXY"]


@pytest.fixture
def host_port_pooling(monkeypatch):

    def get_pooling_key_as_host_with_port(url: str) -> str:
        """
        Test-only override to derive pooling key as "host:port" if port is specified.
        """
        parsed = compat_urlparse(url)
        host = parsed.hostname
        port = parsed.port
        return f"{host}:{port}" if port else host

    monkeypatch.setattr(
        SessionManager,
        "_get_pooling_key_from_url",
        staticmethod(get_pooling_key_as_host_with_port),
    )
    yield
