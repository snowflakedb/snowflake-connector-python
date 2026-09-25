"""Unit tests for TLS context hardening preservation in ssl_wrap_socket.

"""

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import OpenSSL.SSL
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import snowflake.connector.ssl_wrap_socket as ssw  # pylint: disable=import-error
from snowflake.connector.constants import (  # pylint: disable=import-error
    ENV_VAR_MIN_TLS_VERSION,
    ENV_VAR_TLS_CIPHERS,
    OCSPMode,
    get_min_tls_version,
    get_tls_ciphers,
)
from snowflake.connector.errors import OperationalError  # pylint: disable=import-error
from snowflake.connector.vendored.urllib3.util.ssl_ import (  # pylint: disable=import-error
    create_urllib3_context,
)

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
        return ssw.ssl_wrap_socket_with_cert_revocation_checks(
            sock=s,
            server_hostname="localhost",
            ssl_context=src,
            ca_certs=certfile,
        )
    except BaseException:
        s.close()
        raise


def _urllib3_style_context():
    """Build the context urllib3 hands to ``ssl_wrap_socket`` in a real connection.

    requests never populates ``ssl_context``, so urllib3 always constructs one
    itself via ``create_urllib3_context()`` (floor: TLS 1.2) and passes it down.
    Tests that pass ``None`` instead exercise a branch real traffic never takes.
    """
    return create_urllib3_context(ssl_minimum_version=None)


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_env_floor_applied_over_urllib3_supplied_context(monkeypatch):
    """The configured floor must survive the context urllib3 actually supplies.

    Regression guard: the floor used to be applied only when *no* source context
    was supplied. Because urllib3 always supplies one, the mirroring branch put
    the floor back down to urllib3's TLS 1.2 default and the configured minimum
    was silently discarded on every real connection.
    """
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")

    src = _urllib3_style_context()
    assert src.minimum_version == ssl.TLSVersion.TLSv1_2  # what urllib3 gives us

    ctx = ssw._build_context_with_partial_chain(None, src_context=src)

    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_env_floor_never_lowers_a_stricter_caller_floor(monkeypatch):
    """The floor is raise-only: a stricter caller setting must not be weakened."""
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.2")

    src = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    src.minimum_version = ssl.TLSVersion.TLSv1_3

    ctx = ssw._build_context_with_partial_chain(None, src_context=src)

    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_env_floor_unset_preserves_historical_default(monkeypatch):
    """Leaving the variable unset must not change the connector's TLS 1.2 floor."""
    monkeypatch.delenv(ENV_VAR_MIN_TLS_VERSION, raising=False)

    ctx = ssw._build_context_with_partial_chain(
        None, src_context=_urllib3_style_context()
    )

    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("raw", ["1.3", "TLSv1.3", "tlsv1.3", " TLSV1.3 "])
@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_env_floor_accepted_spellings(monkeypatch, raw):
    """Every spelling the Go and JDBC drivers accept resolves to the same floor."""
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, raw)
    assert get_min_tls_version() == ssl.TLSVersion.TLSv1_3


@pytest.mark.parametrize(
    "raw",
    [
        "1.4",
        "TLSv1_1",
        "yes",
        "1,3",
        # Underscore is Python's own enum spelling but not accepted by the other
        # drivers, so it is rejected here too rather than widening the contract
        # past what a cross-driver value can rely on.
        "TLSv1_3",
    ],
)
def test_env_floor_rejects_invalid_values(monkeypatch, raw):
    """An unrecognized value fails loudly instead of falling back to a weaker floor."""
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, raw)
    with pytest.raises(ValueError, match=ENV_VAR_MIN_TLS_VERSION):
        get_min_tls_version()


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_env_floor_is_enforced_end_to_end(tmp_path, monkeypatch):
    """The env floor must fail a real handshake against a TLS-1.2-only server.

    Same shape as the caller-floor test below, but driven purely by the
    environment variable and through the context urllib3 really supplies -- so it
    covers the path every Snowflake API call, stage transfer, OCSP/CRL fetch and
    platform-detection probe takes.
    """
    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)

    def wrap(addr):
        s = socket.socket()
        s.settimeout(5)
        s.connect(addr)
        try:
            return ssw.ssl_wrap_socket_with_cert_revocation_checks(
                sock=s,
                server_hostname="localhost",
                ssl_context=_urllib3_style_context(),
                ca_certs=certfile,
            )
        except BaseException:
            s.close()
            raise

    # Positive control: floor at 1.2 handshakes against the 1.2-only server, so
    # the trust/hostname setup is sound and the failure below is attributable
    # solely to the version floor.
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.2")
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    wrapped = wrap(addr)
    assert wrapped is not None
    wrapped.close()
    stop_evt.wait(5)

    # Negative case: floor at 1.3 must fail the handshake.
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    with pytest.raises(ssl.SSLError):
        wrap(addr)
    stop_evt.wait(5)


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


def _enabled_ciphers(ctx):
    """Cipher names a context would offer, split into (TLS 1.3, TLS 1.2 and below)."""
    names = OpenSSL.SSL.Connection(ctx._ctx, None).get_cipher_list()
    return (
        [n for n in names if n.startswith("TLS_")],
        [n for n in names if not n.startswith("TLS_")],
    )


def test_cipher_policy_unset_leaves_openssl_defaults(monkeypatch):
    """Unconfigured must not narrow anything -- the feature is strictly opt-in."""
    monkeypatch.delenv(ENV_VAR_TLS_CIPHERS, raising=False)
    tls13, tls12 = _enabled_ciphers(ssw._build_context_with_partial_chain(None))
    assert len(tls13) > 1 and len(tls12) > 1


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_cipher_policy_restricts_tls13_suites(monkeypatch):
    """TLS 1.3 suites are restricted, and the TLS 1.2 list is left alone.

    This is the half the standard library cannot reach at all: ``set_ciphers()``
    only governs TLS 1.2 and below, so it works solely because the connector's
    handshakes run on a ``PyOpenSSLContext``.
    """
    monkeypatch.setenv(
        ENV_VAR_TLS_CIPHERS, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
    )
    tls13, tls12 = _enabled_ciphers(ssw._build_context_with_partial_chain(None))
    assert tls13 == ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]
    assert len(tls12) > 1, "TLS 1.2 list should be untouched when only 1.3 is named"


def test_cipher_policy_restricts_tls12_ciphers(monkeypatch):
    """Naming only TLS 1.2 ciphers must not disturb the TLS 1.3 suites."""
    monkeypatch.setenv(ENV_VAR_TLS_CIPHERS, "ECDHE-RSA-AES256-GCM-SHA384")
    tls13, tls12 = _enabled_ciphers(ssw._build_context_with_partial_chain(None))
    assert tls12 == ["ECDHE-RSA-AES256-GCM-SHA384"]
    assert len(tls13) > 1, "TLS 1.3 suites should be untouched when only 1.2 is named"


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_cipher_policy_splits_a_mixed_list(monkeypatch):
    """One variable covers both generations; names route themselves by shape."""
    monkeypatch.setenv(
        ENV_VAR_TLS_CIPHERS, "TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    )
    tls13, tls12 = _enabled_ciphers(ssw._build_context_with_partial_chain(None))
    assert tls13 == ["TLS_AES_256_GCM_SHA384"]
    assert tls12 == ["ECDHE-RSA-AES256-GCM-SHA384"]


@pytest.mark.parametrize("raw", ["NOT_A_CIPHER", "TLS_NOPE_SHA999"])
def test_cipher_policy_rejects_unknown_names(monkeypatch, raw):
    """An unrecognized name must fail loudly, not leave the ciphers unrestricted.

    There is no raise-only clamp for ciphers, so a silently ignored value would
    mean negotiating exactly what the operator meant to exclude.
    """
    monkeypatch.setenv(ENV_VAR_TLS_CIPHERS, raw)
    with pytest.raises(OperationalError, match=ENV_VAR_TLS_CIPHERS):
        ssw._build_context_with_partial_chain(None)


def test_cipher_policy_rejects_a_value_with_no_names(monkeypatch):
    monkeypatch.setenv(ENV_VAR_TLS_CIPHERS, " : ")
    with pytest.raises(ValueError, match=ENV_VAR_TLS_CIPHERS):
        get_tls_ciphers()


@pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")
def test_cipher_policy_changes_the_negotiated_suite(tmp_path, monkeypatch):
    """The configured suite must be the one actually negotiated on the wire.

    Both peers here support all three TLS 1.3 suites, and left alone they settle on
    AES-256. Pinning AES-128 and observing it on the completed handshake shows the
    restriction reached the socket rather than merely being recorded on the context.
    """
    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)

    def negotiated():
        addr, stop_evt = _start_server(certfile, keyfile, None)
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect(addr)
            wrapped = ssw.ssl_wrap_socket_with_cert_revocation_checks(
                sock=sock,
                server_hostname="localhost",
                ssl_context=create_urllib3_context(ssl_minimum_version=None),
                ca_certs=certfile,
            )
            try:
                # WrappedSocket exposes no cipher(); read it off the
                # underlying pyOpenSSL connection.
                return wrapped.connection.get_cipher_name()
            finally:
                wrapped.close()
        finally:
            stop_evt.wait(5)

    monkeypatch.delenv(ENV_VAR_TLS_CIPHERS, raising=False)
    default_suite = negotiated()

    monkeypatch.setenv(ENV_VAR_TLS_CIPHERS, "TLS_AES_128_GCM_SHA256")
    pinned_suite = negotiated()

    assert pinned_suite == "TLS_AES_128_GCM_SHA256"
    assert (
        default_suite != pinned_suite
    ), f"control negotiated {default_suite!r} too, so this proves nothing"
