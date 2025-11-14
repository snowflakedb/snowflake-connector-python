"""Unit tests for SSL wrapper partial-chain context injection."""

import types

import pytest

import snowflake.connector.ssl_wrap_socket as ssw  # pylint: disable=import-error
from snowflake.connector.constants import OCSPMode  # pylint: disable=import-error
from snowflake.connector.vendored.urllib3.contrib.pyopenssl import (  # pylint: disable=import-error
    PyOpenSSLContext,
)


@pytest.fixture(autouse=True)
def disable_ocsp_checks():
    """Disable OCSP checks for offline unit testing."""
    # Ensure wrapper doesn't perform OCSP to keep this unit test offline
    orig = ssw.FEATURE_OCSP_MODE
    ssw.FEATURE_OCSP_MODE = OCSPMode.DISABLE_OCSP_CHECKS
    try:
        yield
    finally:
        ssw.FEATURE_OCSP_MODE = orig


def test_wrapper_injects_pyopenssl_context(monkeypatch):
    """Wrapper should inject a PyOpenSSLContext when none is given."""
    captured = {}

    def fake_ssl_wrap_socket(  # pylint: disable=unused-argument,too-many-arguments,too-many-positional-arguments
        sock, ssl_context=None, **kwargs
    ):
        # Assert that our wrapper provided a PyOpenSSLContext
        captured["ctx_is_pyopenssl"] = isinstance(ssl_context, PyOpenSSLContext)
        # Return a minimal object with a 'connection' attribute expected by wrapper
        return types.SimpleNamespace(connection=None)

    # Patch underlying urllib3 ssl_wrap_socket used by our wrapper
    monkeypatch.setattr(ssw.ssl_, "ssl_wrap_socket", fake_ssl_wrap_socket)

    # Call our wrapper without providing ssl_context; it should inject one
    ssw.ssl_wrap_socket_with_cert_revocation_checks(
        sock=None,
        keyfile=None,
        certfile=None,
        cert_reqs=None,
        ca_certs=None,
        server_hostname="localhost",
        ssl_version=None,
        ciphers=None,
        ssl_context=None,
        ca_cert_dir=None,
        key_password=None,
        ca_cert_data=None,
        tls_in_tls=False,
    )

    assert captured.get("ctx_is_pyopenssl") is True
