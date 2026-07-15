"""Unit tests for TLS context hardening preservation in ssl_wrap_socket."""

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import snowflake.connector.ssl_wrap_socket as ssw  # pylint: disable=import-error
from snowflake.connector.constants import OCSPMode  # pylint: disable=import-error

_HAS_TLS13 = hasattr(ssl.TLSVersion, "TLSv1_3")


@pytest.fixture(autouse=True)
def disable_ocsp_checks():
    """Disable OCSP checks for offline unit testing."""
    orig = ssw.FEATURE_OCSP_MODE
    ssw.FEATURE_OCSP_MODE = OCSPMode.DISABLE_OCSP_CHECKS
    try:
        yield
    finally:
        ssw.FEATURE_OCSP_MODE = orig


def test_default_floor_applied_without_source_context():
    """With no source context, the substituted context restores urllib3's floor."""
    ctx = ssw._build_context_with_partial_chain(None)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_COMPRESSION


def test_hardening_carried_from_stdlib_context():
    """Version floor, options, and verify flags are mirrored from the source."""
    src = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if _HAS_TLS13:
        src.minimum_version = ssl.TLSVersion.TLSv1_3
    src.options |= ssl.OP_NO_TICKET
    src.verify_flags |= ssl.VERIFY_X509_STRICT

    ctx = ssw._build_context_with_partial_chain(None, src_context=src)

    if _HAS_TLS13:
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    # The OP_NO_* bit set by the caller must survive the substitution.
    assert ctx.options & ssl.OP_NO_TICKET
    # Caller verify hardening (strict X.509) must survive as well.
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT


class _SignedOptionsContext(ssl.SSLContext):
    """An ``ssl.SSLContext`` that reports ``options`` the way Windows does.

    On Windows ``ssl.SSLContext.options`` is returned through a signed 32-bit C
    ``long``, so a bitmask with bit 31 set comes back as a *negative* Python
    int. This subclass lets us reproduce that representation on any platform.
    """

    _signed_options = 0

    @property
    def options(self):
        return self._signed_options

    @options.setter
    def options(self, value):
        self._signed_options = value


def test_negative_options_normalized():
    """A negative (Windows signed) mask is recovered to its unsigned form."""
    mask = ssl.OP_NO_COMPRESSION | 0x80000000
    signed = mask - 0x100000000  # how Windows reports it through a 32-bit long
    assert signed < 0
    assert ssw._nonnegative_options(signed) == mask
    # Already-non-negative values (every other platform) are untouched.
    assert ssw._nonnegative_options(ssl.OP_NO_TICKET) == ssl.OP_NO_TICKET


def test_windows_signed_options_do_not_break_handshake():
    """A bit-31 options mask reported as a negative int must not abort the build.

    pyOpenSSL/cryptography marshal options into an unsigned parameter and reject
    a negative with ``OverflowError: can't convert negative number to
    unsigned``. Before normalization this aborted every Windows TLS handshake
    the substituted context must build and still carry the hardening.
    """
    src = _SignedOptionsContext(ssl.PROTOCOL_TLS_CLIENT)
    src.minimum_version = ssl.TLSVersion.TLSv1_2
    src._signed_options = (ssl.OP_NO_COMPRESSION | 0x80000000) - 0x100000000

    ctx = ssw._build_context_with_partial_chain(None, src_context=src)

    # The handshake hardening survives the substitution, recovered as unsigned.
    assert ctx.options & ssl.OP_NO_COMPRESSION
    assert ctx.options & 0x80000000


def _self_signed(host="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert, key


def _write_pem(tmp_path, cert, key):
    """Write cert/key to PEM files under ``tmp_path`` and return their paths."""
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile)


def _serve_once(certfile, keyfile, max_version, ready_evt, addr_holder, stop_evt):
    """Single-shot TLS server capped at ``max_version``; accepts one connection."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if max_version is not None:
        ctx.maximum_version = max_version
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

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
                pass
    finally:
        s.close()
        stop_evt.set()


def _start_server(certfile, keyfile, max_version):
    """Start a single-shot TLS server in a daemon thread; return (addr, stop_evt)."""
    ready_evt, stop_evt, addr_holder = threading.Event(), threading.Event(), []
    t = threading.Thread(
        target=_serve_once,
        args=(certfile, keyfile, max_version, ready_evt, addr_holder, stop_evt),
        daemon=True,
    )
    t.start()
    ready_evt.wait(5)
    return addr_holder[0], stop_evt


def _wrap(certfile, client_min_version, addr):
    """Drive the connector handshake against ``addr`` with a caller TLS floor.

    The server cert is trusted via ``ca_certs`` and its SAN matches
    ``localhost``, so certificate and hostname verification both pass. The TLS
    version floor is therefore the *only* thing that can fail the handshake,
    which is what isolates the behavior under test.
    """
    src = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    src.minimum_version = client_min_version
    s = socket.socket()
    s.settimeout(5)
    s.connect(addr)
    try:
        return ssw.ssl_wrap_socket_with_ocsp(
            sock=s,
            server_hostname="localhost",
            ssl_context=src,
            ca_certs=certfile,
        )
    except BaseException:
        s.close()
        raise


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_caller_version_floor_is_enforced_end_to_end(tmp_path):
    """A caller-supplied TLS 1.3 floor must be honored, not discarded.

    The cert is trusted and the hostname matches, so the handshake's only
    possible failure is the version floor. Against a TLS-1.2-only server:

    * a matching TLS 1.2 floor succeeds (positive control — proves the trust /
      hostname setup is sound, so the failure below is attributable solely to
      the version floor, not to an unrelated cert/hostname error), and
    * a TLS 1.3 floor fails. Before the fix the floor was dropped during the
      PyOpenSSLContext substitution and this connection silently succeeded.
    """
    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)

    # Positive control: a matching TLS 1.2 floor handshakes successfully.
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    wrapped = _wrap(certfile, ssl.TLSVersion.TLSv1_2, addr)
    assert wrapped is not None
    wrapped.close()
    stop_evt.wait(5)

    # Negative case: a TLS 1.3 floor against a TLS-1.2-only server must fail.
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    with pytest.raises(ssl.SSLError):
        _wrap(certfile, ssl.TLSVersion.TLSv1_3, addr)
    stop_evt.wait(5)
