"""Integration-style unit test for partial-chain TLS handshake."""

import ipaddress as _ip
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


@pytest.fixture(autouse=True)
def disable_ocsp_checks():
    """Disable OCSP checks for offline unit testing."""
    orig = ssw.FEATURE_OCSP_MODE
    ssw.FEATURE_OCSP_MODE = OCSPMode.DISABLE_OCSP_CHECKS
    try:
        yield
    finally:
        ssw.FEATURE_OCSP_MODE = orig


def _create_key():
    """Create a new RSA key for certificate generation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _create_cert(subject_cn, issuer_cert, issuer_key, is_ca, subject_key, ca=False):
    """Create a certificate signed by issuer or self-signed if issuer is None."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer_name = subject if issuer_cert is None else issuer_cert.subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = (
            builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(_ip.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
        )

    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
        critical=False,
    )
    # Authority Key Identifier (referencing issuer public key)
    authority_pubkey = (
        subject_key.public_key() if issuer_key is None else issuer_key.public_key()
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_pubkey),
        critical=False,
    )

    signer_key = issuer_key if issuer_key is not None else subject_key
    cert = builder.sign(private_key=signer_key, algorithm=hashes.SHA256())
    return cert


def _pem(obj, is_key=False):
    """Return PEM-encoded certificate or key."""
    if is_key:
        return obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    return obj.public_bytes(encoding=serialization.Encoding.PEM)


def _run_tls_server(server_cert_pem, server_key_pem, chain_pem, ready_evt, addr_holder):
    """Run a minimal TLS server presenting server+intermediate chain."""
    # Minimal TLS server using Python ssl to present server+intermediate chain
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Combine server and intermediate into one PEM for certfile
    with _tempfile.NamedTemporaryFile(delete=False) as cert_chain_file:
        cert_chain_file.write(server_cert_pem)
        cert_chain_file.write(chain_pem)
        cert_chain_file.flush()
        certfile_path = cert_chain_file.name
    with _tempfile.NamedTemporaryFile(delete=False) as key_file:
        key_file.write(server_key_pem)
        key_file.flush()
        keyfile_path = key_file.name
    ctx.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    addr = s.getsockname()
    addr_holder.append(addr)
    ready_evt.set()
    with ctx.wrap_socket(s, server_side=True) as ssock:
        conn, _ = ssock.accept()
        conn.close()
    s.close()


def test_partial_chain_handshake_succeeds_with_intermediate_as_anchor():
    """Client should handshake trusting only the intermediate as anchor."""
    # Generate Root -> Intermediate -> Server
    root_key = _create_key()
    root_cert = _create_cert("Root", None, None, True, root_key)

    inter_key = _create_key()
    inter_cert = _create_cert("Intermediate", root_cert, root_key, True, inter_key)

    server_key = _create_key()
    server_cert = _create_cert("Server", inter_cert, inter_key, False, server_key)

    # Start TLS server presenting server + intermediate chain
    ready_evt = threading.Event()
    addr_holder = []
    t = threading.Thread(
        target=_run_tls_server,
        args=(
            _pem(server_cert),
            _pem(server_key, True),
            _pem(inter_cert),
            ready_evt,
            addr_holder,
        ),
    )
    t.daemon = True
    t.start()
    ready_evt.wait(5)
    host, port = addr_holder[0]

    # Build PyOpenSSL context with only intermediate as trust anchor
    ctx = ssw._build_context_with_partial_chain(
        None
    )  # pylint: disable=protected-access
    # Load intermediate into store via PEM file path by reusing helper
    with _tempfile.NamedTemporaryFile(delete=False) as caf:
        caf.write(_pem(inter_cert))
        caf.flush()
        ctx.load_verify_locations(cafile=caf.name)

    # Wrap a socket with our wrapper specifying our context
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))

    # The wrapper expects kwargs similar to urllib3; use provided context
    ws = ssw.ssl_wrap_socket_with_ocsp(
        sock=s,
        server_hostname="localhost",
        ssl_context=ctx,
    )
    # If we reached here without SSL error, TLS handshake succeeded with
    # intermediate-only trust; access attribute to assert presence
    assert hasattr(ws, "connection")
    s.close()
