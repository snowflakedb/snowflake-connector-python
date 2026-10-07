"""SNOW-4232077: vendored pyOpenSSL must import without ssl.PROTOCOL_TLSv1."""

import importlib
import ssl
import sys

import OpenSSL.SSL
import pytest

from snowflake.connector.vendored.urllib3 import util

_PYOPENSSL = "snowflake.connector.vendored.urllib3.contrib.pyopenssl"
# OpenSSL 4 drops the whole legacy PROTOCOL_TLSv1* family, not only TLS 1.0.
_REMOVED_ON_OPENSSL4 = ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2")


def test_protocol_tlsv1_mapped_when_stdlib_exposes_it():
    """TLS 1.0 stays mapped on interpreters that still define the constant."""
    if not hasattr(ssl, "PROTOCOL_TLSv1") or not hasattr(OpenSSL.SSL, "TLSv1_METHOD"):
        pytest.skip("this interpreter does not expose TLS 1.0 constants")

    pyopenssl = importlib.import_module(_PYOPENSSL)
    assert pyopenssl._openssl_versions[ssl.PROTOCOL_TLSv1] is OpenSSL.SSL.TLSv1_METHOD


def test_pyopenssl_imports_without_protocol_tlsv1():
    """Import and PROTOCOL_TLS_CLIENT contexts succeed when TLS 1.0 is absent.

    Python built against OpenSSL 4 omits ssl.PROTOCOL_TLSv1. The vendored
    module used to dereference that attribute while building its protocol map,
    so importing the connector failed before any connection was attempted.
    """
    removed = []
    for name in _REMOVED_ON_OPENSSL4:
        if hasattr(ssl, name):
            removed.append((name, getattr(ssl, name)))
            delattr(ssl, name)

    sys.modules.pop(_PYOPENSSL, None)
    try:
        pyopenssl = importlib.import_module(_PYOPENSSL)
        assert util.ssl_.PROTOCOL_TLS_CLIENT in pyopenssl._openssl_versions
        if hasattr(OpenSSL.SSL, "TLSv1_METHOD"):
            assert OpenSSL.SSL.TLSv1_METHOD not in pyopenssl._openssl_versions.values()
        context = pyopenssl.PyOpenSSLContext(util.ssl_.PROTOCOL_TLS_CLIENT)
        assert context.protocol == OpenSSL.SSL.SSLv23_METHOD
    finally:
        for name, value in removed:
            setattr(ssl, name, value)
        sys.modules.pop(_PYOPENSSL, None)
        importlib.import_module(_PYOPENSSL)
