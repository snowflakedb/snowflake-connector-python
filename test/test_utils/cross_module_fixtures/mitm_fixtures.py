"""Mitmproxy fixtures for testing."""

import shutil
from typing import Any, Generator, Union

import pytest

from ..mitm import MitmClient


@pytest.fixture(scope="session")
def mitm_proxy() -> Generator[Union[MitmClient, Any], Any, None]:
    """Start mitmproxy for transparent HTTPS proxying in tests.

    This fixture (session-scoped):
    - Starts mitmdump once for all tests
    - Waits for CA certificate generation
    - Returns MitmClient instance
    - Cleans up after all tests complete

    The fixture does NOT automatically configure proxy settings.
    Tests should explicitly use the proxy via:
    1. Environment variables: mitm_proxy.set_env_vars(monkeypatch)
    2. Connection parameters: conn_cnx(proxy_host=mitm_proxy.host, ...)

    Yields:
        MitmClient: Running mitmproxy client instance

    Skips:
        When mitmdump binary is not available (e.g., Python 3.14+ where
        mitmproxy is excluded from [development] extras because transitive
        dependencies aioquic/pylsqpack lack compatible wheels).

    Fails:
        When RuntimeError: If mitmproxy is installed but fails to start
    """
    # mitmproxy is excluded for Python 3.14+ in setup.cfg; skip dynamically
    # so tests auto-re-enable when upstream wheels become available.
    if not shutil.which("mitmdump"):
        pytest.skip("mitmdump not available (mitmproxy not installed)")
    try:
        with MitmClient() as client:
            yield client
    except (RuntimeError, TimeoutError) as e:
        pytest.fail(f"Failed to start mitmproxy: {e}")
