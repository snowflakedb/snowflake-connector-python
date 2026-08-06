"""Unit tests for TLS hostname verification in ssl_wrap_socket and regression tests for SNOW-3675579."""

import ipaddress as _ip
import os as _os
import socket
import ssl
import tempfile as _tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import snowflake.connector.ssl_wrap_socket as ssw  # pylint: disable=import-error
from snowflake.connector.constants import OCSPMode  # pylint: disable=import-error
from snowflake.connector.vendored.urllib3.util.ssl_match_hostname import (
    CertificateError,
)


@pytest.fixture(autouse=True)
def disable_ocsp_checks():
    """Disable OCSP checks for offline unit testing."""
    orig = ssw.FEATURE_OCSP_MODE
    ssw.FEATURE_OCSP_MODE = OCSPMode.DISABLE_OCSP_CHECKS
    try:
        yield
    finally:
        ssw.FEATURE_OCSP_MODE = orig


def _create_self_signed_cert(common_name, dns_names):
    """Create a self-signed leaf certificate with the given SAN DNS names."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    san_entries = [x509.DNSName(d) for d in dns_names]
    san_entries.append(x509.IPAddress(_ip.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert, key


def _pem_cert(cert):
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def _pem_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _run_tls_server(cert_pem, key_pem, ready_evt, addr_holder, stop_evt):
    """Run a minimal one-shot TLS server presenting the given certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with _tempfile.NamedTemporaryFile(delete=False) as cert_file:
        cert_file.write(cert_pem)
        cert_file.flush()
        certfile_path = cert_file.name
    with _tempfile.NamedTemporaryFile(delete=False) as key_file:
        key_file.write(key_pem)
        key_file.flush()
        keyfile_path = key_file.name
    try:
        ctx.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
    finally:
        _os.unlink(certfile_path)
        _os.unlink(keyfile_path)

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    addr_holder.append(s.getsockname())
    ready_evt.set()
    try:
        with ctx.wrap_socket(s, server_side=True) as ssock:
            try:
                conn, _ = ssock.accept()
                conn.close()
            except (ssl.SSLError, OSError):
                # Client may abort the handshake / connection on hostname
                # mismatch; that is expected for the negative test.
                pass
    finally:
        s.close()
        stop_evt.set()


def _start_server(cert, key):
    ready_evt = threading.Event()
    stop_evt = threading.Event()
    addr_holder = []
    t = threading.Thread(
        target=_run_tls_server,
        args=(_pem_cert(cert), _pem_key(key), ready_evt, addr_holder, stop_evt),
        daemon=True,
    )
    t.start()
    ready_evt.wait(5)
    return addr_holder[0], stop_evt


def _client_context_trusting(cert):
    """Build the connector's PyOpenSSL context trusting *cert* as anchor."""
    ctx = ssw._build_context_with_partial_chain(None)
    with _tempfile.NamedTemporaryFile(delete=False) as caf:
        caf.write(_pem_cert(cert))
        caf.flush()
        cafile_path = caf.name
    try:
        ctx.load_verify_locations(cafile=cafile_path)
    finally:
        _os.unlink(cafile_path)
    return ctx


def test_hostname_mismatch_is_rejected():
    """A valid chain with the wrong hostname must be rejected."""
    # Certificate is valid and trusted, but its SAN is 'localhost' only.
    cert, key = _create_self_signed_cert("localhost", ["localhost"])
    (host, port), stop_evt = _start_server(cert, key)

    ctx = _client_context_trusting(cert)
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))

    with pytest.raises(CertificateError):
        ssw.ssl_wrap_socket_with_cert_revocation_checks(
            sock=s,
            server_hostname="not-the-right-host.example.com",
            ssl_context=ctx,
        )
    s.close()
    stop_evt.wait(5)


def test_hostname_match_succeeds():
    """A valid chain whose SAN matches the requested host must be accepted."""
    cert, key = _create_self_signed_cert("localhost", ["localhost"])
    (host, port), stop_evt = _start_server(cert, key)

    ctx = _client_context_trusting(cert)
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))

    ws = ssw.ssl_wrap_socket_with_cert_revocation_checks(
        sock=s,
        server_hostname="localhost",
        ssl_context=ctx,
    )
    assert hasattr(ws, "connection")
    s.close()
    stop_evt.wait(5)


def test_missing_hostname_is_rejected_when_verification_required():
    """No server hostname under CERT_REQUIRED must fail closed, not fail open.

    Without a hostname the peer's identity cannot be asserted, so the check must
    not be skipped. The verify_mode check runs first, so a genuine CERT_NONE
    opt-out is still honored (see the test below).
    """
    cert, key = _create_self_signed_cert("localhost", ["localhost"])
    (host, port), stop_evt = _start_server(cert, key)

    ctx = _client_context_trusting(cert)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))

    with pytest.raises(CertificateError):
        ssw.ssl_wrap_socket_with_cert_revocation_checks(
            sock=s,
            server_hostname=None,
            ssl_context=ctx,
        )
    s.close()
    stop_evt.wait(5)


def test_missing_hostname_is_allowed_when_verification_disabled():
    """CERT_NONE is an explicit opt-out, so a missing hostname is tolerated.

    The verify_mode check is evaluated before the hostname check precisely so a
    caller who disabled verification is not forced to supply a hostname.
    """
    cert, key = _create_self_signed_cert("localhost", ["localhost"])
    (host, port), stop_evt = _start_server(cert, key)

    ctx = _client_context_trusting(cert)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))

    ws = ssw.ssl_wrap_socket_with_cert_revocation_checks(
        sock=s,
        server_hostname=None,
        ssl_context=ctx,
    )
    assert hasattr(ws, "connection")
    s.close()
    stop_evt.wait(5)
