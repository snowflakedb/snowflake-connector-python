"""The configured TLS floor must reach every request the connector sends.

``test_ssl_context_hardening`` covers the context-construction seam directly.
These tests go one layer out and drive real requests through ``SessionManager``
-- the machinery every non-login request shares, stage transfers included (see
``storage_client._send_request_with_retry``, which either borrows the
connection's session or builds a ``SessionManager`` on the fly). If the floor
were dropped anywhere between ``SessionManager`` and the socket, these fail.
"""

from __future__ import annotations

import socket
import ssl
import threading

import pytest

import snowflake.connector.ssl_wrap_socket as ssw  # pylint: disable=import-error
from snowflake.connector.constants import (  # pylint: disable=import-error
    ENV_VAR_MIN_TLS_VERSION,
    OCSPMode,
)
from snowflake.connector.errorcode import (  # pylint: disable=import-error
    ER_INVALID_VALUE,
)
from snowflake.connector.errors import (  # pylint: disable=import-error
    NonRetryableTlsError,
    OperationalError,
    ProgrammingError,
)
from snowflake.connector.options import (  # pylint: disable=import-error
    installed_azure_identity,
    installed_boto,
)
from snowflake.connector.session_manager import (  # pylint: disable=import-error
    SessionManager,
    build_azure_transport,
)
from snowflake.connector.vendored.requests.exceptions import (  # pylint: disable=import-error
    SSLError,
)

from .test_ssl_context_hardening import _self_signed, _start_server, _write_pem

_HAS_TLS13 = hasattr(ssl.TLSVersion, "TLSv1_3")

pytestmark = pytest.mark.skipif(not _HAS_TLS13, reason="TLS 1.3 not available")


@pytest.fixture(autouse=True)
def _offline_tls():
    """Disable revocation checking so the version floor is the only failure mode."""
    orig = ssw.FEATURE_OCSP_MODE
    ssw.FEATURE_OCSP_MODE = OCSPMode.DISABLE_OCSP_CHECKS
    # The floor is applied inside the connector's ssl_wrap_socket replacement, so
    # the interception has to be installed for this to mean anything. Importing
    # snowflake.connector.network normally does it; make it explicit and
    # idempotent so the test does not depend on import order.
    ssw.inject_into_urllib3()
    try:
        yield
    finally:
        ssw.FEATURE_OCSP_MODE = orig


def _persistent_tls_server(certfile, keyfile, max_version):
    """A TLS server that keeps accepting, answering each request with HTTP 400.

    ``test_ssl_context_hardening._start_server`` serves exactly one connection,
    which is enough when the client makes a single attempt. azure-identity/MSAL
    retries, and against a single-shot server the retries hit a closed socket --
    the real TLS error then gets buried under "Max retries exceeded / Connection
    refused". Staying up keeps the first failure visible, and answering HTTP means
    a completed handshake fails *above* TLS, which is what the control asserts.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if max_version is not None:
        ctx.maximum_version = max_version
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.3)
    addr = srv.getsockname()
    stop_evt = threading.Event()

    def serve():
        while not stop_evt.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(4096)
                    tls_conn.sendall(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                    )
            except (ssl.SSLError, OSError):
                pass  # handshake rejected by either side; the client asserts on it
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return addr, stop_evt


def _get(url: str, certfile: str):
    # max_retries=0 so a handshake rejection surfaces as itself rather than as a
    # retry-exhaustion error against an already-closed single-shot server.
    manager = SessionManager(use_pooling=False, max_retries=0)
    return manager.get(url, timeout=5, verify=certfile)


def test_session_manager_request_honors_floor(tmp_path, monkeypatch):
    """A 1.3 floor must fail a SessionManager request to a TLS-1.2-only server.

    The positive control runs first: with a matching 1.2 floor the same request
    succeeds, which proves the cert trust and hostname setup are sound so the
    failure below is attributable to the version floor alone.
    """
    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)

    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.2")
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    # The single-shot server closes the connection right after the handshake, so
    # the HTTP response never arrives; completing the handshake is the assertion.
    with pytest.raises(Exception) as positive:
        _get(f"https://localhost:{addr[1]}/", certfile)
    assert not isinstance(
        positive.value, SSLError
    ), f"TLS 1.2 floor should reach a TLS-1.2-only server, got {positive.value!r}"
    stop_evt.wait(5)

    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    with pytest.raises(SSLError) as negative:
        _get(f"https://localhost:{addr[1]}/", certfile)
    stop_evt.wait(5)

    # The ticket requires the cause be diagnosable, not a bare connection error.
    assert (
        "version" in str(negative.value).lower()
        or "protocol" in str(negative.value).lower()
    ), f"error should name the protocol/version mismatch: {negative.value!r}"


@pytest.mark.skipif(not installed_boto, reason="requires boto3/botocore")
def test_botocore_requests_honor_floor(tmp_path, monkeypatch):
    """AWS SDK requests must honor the floor too.

    botocore builds its contexts with its own private ``create_urllib3_context``
    and sends them through the *real* urllib3, so the vendored-urllib3 patch does
    not reach it; ``inject_min_tls_version_into_botocore`` hooks it separately.
    Without that hook botocore negotiates TLS 1.2 here and the handshake below
    silently succeeds.

    This is also the canary for the private-API dependency: if botocore ever
    renames or stops routing through ``create_urllib3_context``, this fails
    loudly instead of the floor quietly disappearing.
    """
    from botocore.awsrequest import AWSRequest
    from botocore.httpsession import URLLib3Session

    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)
    ssw.inject_min_tls_version_into_botocore()  # idempotent; explicit for import order

    def send(addr):
        return URLLib3Session(verify=certfile, timeout=5).send(
            AWSRequest("GET", f"https://localhost:{addr[1]}/").prepare()
        )

    # Positive control: a 1.3-capable server handshakes, so a later HTTP-level
    # error (the single-shot server closes the socket) means TLS itself passed.
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")
    addr, stop_evt = _start_server(certfile, keyfile, None)
    with pytest.raises(Exception) as control:
        send(addr)
    assert (
        "SSL" not in type(control.value).__name__
    ), f"TLS 1.3 floor should handshake with a TLS-1.3 server, got {control.value!r}"
    stop_evt.wait(5)

    # A 1.2-only server must be refused at the protocol level.
    addr, stop_evt = _start_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    with pytest.raises(Exception) as negative:
        send(addr)
    stop_evt.wait(5)
    assert (
        "SSL" in type(negative.value).__name__
    ), f"expected a TLS failure, got {negative.value!r}"
    assert (
        "protocol version" in str(negative.value).lower()
    ), f"error should name the protocol version mismatch: {negative.value!r}"


@pytest.mark.skipif(
    not installed_azure_identity, reason="requires azure-identity/azure-core"
)
def test_azure_identity_requests_honor_floor(tmp_path, monkeypatch):
    """azure-core credentials must honor the floor too.

    azure-identity drives its token requests through the real requests/urllib3, so
    the vendored patch never sees them. ``build_azure_transport()`` hands
    the credential a session whose floor we control, via azure-core's public
    ``transport=`` keyword. Driven through a real ``WorkloadIdentityCredential``
    so it covers the wiring, not just the transport in isolation.
    """
    from snowflake.connector.options import azure_identity

    from .test_ssl_context_hardening import _self_signed, _write_pem

    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)
    token_file = tmp_path / "federated-token"
    token_file.write_text("dummy.jwt.token")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", certfile)  # trust the local server
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")

    def fetch(addr):
        transport = build_azure_transport()
        with azure_identity.WorkloadIdentityCredential(
            tenant_id="tenant",
            client_id="client",
            token_file_path=str(token_file),
            authority=f"https://localhost:{addr[1]}",
            disable_instance_discovery=True,
            transport=transport,
        ) as credential:
            credential.get_token("https://management.azure.com/.default")

    # A TLS-1.2-only server must be refused at the protocol level.
    addr, stop_evt = _persistent_tls_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    try:
        with pytest.raises(Exception) as negative:
            fetch(addr)
    finally:
        stop_evt.set()
    assert (
        "protocol version" in str(negative.value).lower()
    ), f"expected a TLS protocol-version failure, got {negative.value!r}"

    # Positive control: against a TLS-1.3 server the handshake completes and the
    # request fails above TLS instead (the stub server answers HTTP 400).
    addr, stop_evt = _persistent_tls_server(certfile, keyfile, None)
    try:
        with pytest.raises(Exception) as control:
            fetch(addr)
    finally:
        stop_evt.set()
    assert (
        "protocol version" not in str(control.value).lower()
    ), f"TLS 1.3 floor should handshake with a TLS-1.3 server, got {control.value!r}"


@pytest.mark.skipif(not installed_boto, reason="requires boto3/botocore")
def test_botocore_hook_is_idempotent():
    """Re-injecting must not stack wrappers on top of each other."""
    import botocore.httpsession

    ssw.inject_min_tls_version_into_botocore()
    first = botocore.httpsession.create_urllib3_context
    ssw.inject_min_tls_version_into_botocore()
    assert botocore.httpsession.create_urllib3_context is first


def test_connect_rejects_invalid_floor_before_any_io(monkeypatch):
    """A malformed floor is a connection-time ProgrammingError, not a late ValueError.

    Without the connect-time check the bad value would surface as a bare
    ``ValueError`` raised from inside the HTTP stack during the first handshake,
    which neither names the connection attempt nor fits the DB-API error model.
    """
    import snowflake.connector

    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.4")

    with pytest.raises(ProgrammingError) as exc:
        # Bogus credentials on purpose: validation must reject the value before
        # any network I/O is attempted, so these are never used.
        snowflake.connector.connect(account="acct", user="u", password="p")

    assert exc.value.errno == ER_INVALID_VALUE
    assert ENV_VAR_MIN_TLS_VERSION in str(exc.value)


def test_session_manager_request_succeeds_at_negotiated_floor(tmp_path, monkeypatch):
    """A 1.3 floor against a 1.3-capable server must complete the handshake.

    Guards the opposite mistake from the test above: a floor implemented by
    breaking every handshake would pass a negative-only test.
    """
    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)

    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")
    # max_version=None -> server offers up to its maximum, so 1.3 is negotiated.
    addr, stop_evt = _start_server(certfile, keyfile, None)
    with pytest.raises(Exception) as exc:
        _get(f"https://localhost:{addr[1]}/", certfile)
    assert not isinstance(
        exc.value, SSLError
    ), f"TLS 1.3 floor should handshake with a TLS-1.3 server, got {exc.value!r}"
    stop_evt.wait(5)


def test_non_retryable_tls_error_surfaces_from_connect(tmp_path, monkeypatch):
    """A TLS failure a retry cannot fix must surface with its diagnosis.

    ``connect()`` used to report ``250001: Could not connect to Snowflake backend
    after 2 attempt(s)`` plus a firewall-troubleshooting hint for this, because the
    auth layer funnels every ``OperationalError`` from ``authenticate()`` into a
    retry-until-timeout loop and then replaces it. The network layer had already
    classified the failure correctly and named the cause; it just never reached the
    caller. An operator who set the floor was pointed at their firewall.
    """
    import snowflake.connector

    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", certfile)
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")

    addr, stop_evt = _persistent_tls_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    try:
        with pytest.raises(NonRetryableTlsError) as exc:
            snowflake.connector.connect(
                account="testaccount",
                user="u",
                password="p",
                host="localhost",
                port=addr[1],
                disable_ocsp_checks=True,
                login_timeout=15,
                network_timeout=15,
            )
    finally:
        stop_evt.set()

    assert "protocol version" in str(exc.value).lower()
    # Still an OperationalError, so callers catching the broader type keep working.
    assert isinstance(exc.value, OperationalError)


def test_stage_transfer_surfaces_non_retryable_tls_error(tmp_path, monkeypatch):
    """The "fail later" scenario: the API leg is fine, the stage endpoint is not.

    A cloud-storage endpoint that cannot meet the floor must fail the *transfer*,
    with the cause named -- not the connection. This is the second half of the
    coverage question: the Snowflake API and stage transfers reach the network
    through different call paths, so a test that only exercises ``connect()``
    would pass even if stage transfers ignored the floor entirely.

    It also guards a second swallow point. requests' ``SSLError`` subclasses
    ``ConnectionError``, which is in ``SnowflakeStorageClient.TRANSIENT_ERRORS``,
    so before the fix a handshake rejection was retried ``max_retry`` times with
    exponential backoff and then reported as ``RequestExceedMaxRetryError: ...
    failed for exceeding maximum retries``, with no mention of TLS.

    GCS is used deliberately: it builds path-style ``{endpoint}/{bucket}/{path}``
    URLs from ``stage_info["endPoint"]``, so the stage can point at a local server
    directly. S3 would produce ``https://{bucket}.{endPoint}``, and resolution of
    ``*.localhost`` subdomains is platform-dependent.
    """
    from unittest import mock

    from snowflake.connector.cursor import SnowflakeCursor
    from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent

    cert, key = _self_signed()
    certfile, keyfile = _write_pem(tmp_path, cert, key)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", certfile)
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")

    payload = tmp_path / "payload.txt"
    payload.write_text("hello")

    cursor = mock.MagicMock(autospec=SnowflakeCursor)
    # With a mocked connection the storage client would borrow its mocked session
    # and never touch the network; None routes it through a real SessionManager,
    # which is the path a stage transfer actually takes.
    cursor.connection = None

    addr, stop_evt = _persistent_tls_server(certfile, keyfile, ssl.TLSVersion.TLSv1_2)
    try:
        agent = SnowflakeFileTransferAgent(
            cursor,
            f"PUT file://{payload} @~/stage",
            {
                "data": {
                    "command": "UPLOAD",
                    "src_locations": [str(payload)],
                    "sourceCompression": "none",
                    "stageInfo": {
                        "locationType": "GCS",
                        "location": "bucket/path/",
                        "path": "path/",
                        "region": "us-central1",
                        "endPoint": f"localhost:{addr[1]}",
                        "creds": {"GCS_ACCESS_TOKEN": "token"},
                    },
                },
                "success": True,
            },
        )
        agent.execute()
    finally:
        stop_evt.set()

    result = agent._results[0]
    assert isinstance(
        result.error_details, NonRetryableTlsError
    ), f"stage transfer should report the TLS failure, got {result.error_details!r}"
    assert "protocol version" in str(result.error_details).lower()


@pytest.mark.skipif(
    not installed_azure_identity, reason="requires azure-identity/azure-core"
)
def test_azure_transport_floors_the_proxy_manager_too(monkeypatch):
    """HTTPS-through-a-proxy must honor the floor as well as direct HTTPS.

    requests builds a separate manager for proxied HTTPS via ``proxy_manager_for``
    and does not carry ``init_poolmanager``'s pool kwargs across to it -- it keeps
    only connections/maxsize/block, for pickling. Overriding only
    ``init_poolmanager`` therefore left proxied Azure token fetches at whatever
    floor OpenSSL defaulted to.
    """
    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")

    transport = build_azure_transport()
    try:
        adapter = transport.session.get_adapter("https://example.invalid/")
        direct = adapter.poolmanager.connection_pool_kw.get("ssl_context")
        proxied = adapter.proxy_manager_for(
            "http://proxy.invalid:8080"
        ).connection_pool_kw.get("ssl_context")
    finally:
        transport.close()

    assert direct is not None and proxied is not None
    assert direct.minimum_version == ssl.TLSVersion.TLSv1_3
    assert proxied.minimum_version == ssl.TLSVersion.TLSv1_3


@pytest.mark.skipif(not installed_boto, reason="requires boto3/botocore")
def test_botocore_hook_failure_is_reported_only_when_floor_configured(monkeypatch):
    """A botocore rename must fail the connections that rely on the floor -- only those.

    The hook depends on botocore's private ``create_urllib3_context``. Reaching for
    it unguarded raised ``AttributeError`` while *importing* the connector, which
    would break every user on an unrelated botocore upgrade. It is now recorded and
    surfaced at connect time to callers who configured a floor, and merely logged
    for everyone else.
    """
    import botocore.httpsession

    import snowflake.connector

    monkeypatch.delattr(botocore.httpsession, "create_urllib3_context")
    monkeypatch.setattr(ssw, "BOTOCORE_MIN_TLS_HOOK_ERROR", None)

    ssw.inject_min_tls_version_into_botocore()  # must not raise
    assert ssw.BOTOCORE_MIN_TLS_HOOK_ERROR is not None

    monkeypatch.setenv(ENV_VAR_MIN_TLS_VERSION, "1.3")
    with pytest.raises(ProgrammingError, match=ENV_VAR_MIN_TLS_VERSION) as exc:
        snowflake.connector.connect(account="acct", user="u", password="p")
    assert exc.value.errno == ER_INVALID_VALUE

    # Unset: the missing hook is not this caller's problem, so connect() gets as far
    # as the network instead of being refused.
    monkeypatch.delenv(ENV_VAR_MIN_TLS_VERSION, raising=False)
    with pytest.raises(Exception) as unset:
        snowflake.connector.connect(
            account="acct", user="u", password="p", login_timeout=1
        )
    assert not isinstance(
        unset.value, ProgrammingError
    ) or ENV_VAR_MIN_TLS_VERSION not in str(unset.value)
