import os

import pytest


@pytest.fixture
def proxy_env_vars():
    """Manages HTTP_PROXY and HTTPS_PROXY environment variables for testing."""
    original_http_proxy = os.environ.get("HTTP_PROXY")
    original_https_proxy = os.environ.get("HTTPS_PROXY")

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
