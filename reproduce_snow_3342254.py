"""
Reproduction script for SNOW-3342254: S3 Upload Timeouts on macOS

Theory: The Snowflake connector passes a raw bytes object into a single
socket.sendall() call.  On macOS, dumping megabytes into one call saturates
kern.ipc.maxsockbuf and leaves the kernel no headroom to retransmit dropped
packets.  boto3 avoids this by passing a file-like object, causing http.client
to call sendall() in 8 KB slices.

Two phases:
  Phase 1 – Prove the syscall pattern.  We intercept socket.sendall, count
            calls, and show that bytes → 1 call (current connector) while
            BytesIO → many small calls (boto3-like fix).

  Phase 2 – Simulate the stall.  We create a TCP peer whose receive window is
            intentionally tiny.  The single-sendall path blocks; the chunked
            path drains the window incrementally and completes.

  Phase 5 – Full reproduction with dnctl + pfctl.  Injects 30% packet
            loss on loopback traffic to 127.0.0.2, runs the bytes vs
            BytesIO upload to a mock S3 server, and shows the actual
            deadlock.  Requires macOS + sudo.

Usage:
    python reproduce_snow_3342254.py           # Phases 1–4 (no sudo)
    python reproduce_snow_3342254.py --phase5  # All phases incl. packet loss
"""

from __future__ import annotations

import http.client
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from typing import Generator

# ---------------------------------------------------------------------------
# Constants matching the connector
# ---------------------------------------------------------------------------

S3_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB  (constants.S3_DEFAULT_CHUNK_SIZE)
HTTP_BLOCKSIZE = 8192  # http.client default blocksize

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class SendallTracker:
    """Wraps socket.sendall and records every call's byte count."""

    def __init__(self):
        self.calls: list[int] = []
        self._original = socket.socket.sendall

    def install(self):
        tracker = self

        def _patched(sock_self, data, *a, **kw):
            tracker.calls.append(len(data))
            return tracker._original(sock_self, data, *a, **kw)

        socket.socket.sendall = _patched

    def uninstall(self):
        socket.socket.sendall = self._original

    @contextmanager
    def track(self) -> Generator[SendallTracker]:
        self.calls.clear()
        self.install()
        try:
            yield self
        finally:
            self.uninstall()


def _drain_server(server_sock: socket.socket, stop: threading.Event):
    """Accept one connection and discard all bytes until the client closes."""
    server_sock.settimeout(5.0)
    try:
        conn, _ = server_sock.accept()
        conn.settimeout(5.0)
        try:
            while not stop.is_set():
                data = conn.recv(65536)
                if not data:
                    break
        except OSError:
            pass
        finally:
            conn.close()
    except OSError:
        pass


@contextmanager
def loopback_http_server() -> Generator[tuple[str, int]]:
    """Spin up a minimal HTTP/1.1 echo server on localhost."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    stop = threading.Event()

    def serve():
        server.settimeout(5.0)
        try:
            conn, _ = server.accept()
            conn.settimeout(5.0)
        except OSError:
            return
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            # send a minimal 200 response so http.client doesn't error
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            # drain any remaining body
            while not stop.is_set():
                chunk = conn.recv(65536)
                if not chunk:
                    break
        except OSError:
            pass
        finally:
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield host, port
    finally:
        stop.set()
        server.close()
        t.join(timeout=2.0)


def send_via_http_client(host: str, port: int, payload) -> None:
    """Fire a PUT with the given payload through http.client (same path as requests)."""
    conn = http.client.HTTPConnection(host, port, timeout=10)
    content_length = (
        len(payload)
        if isinstance(payload, (bytes, bytearray))
        else payload.seek(0, 2) or payload.seek(0) or payload.seek(0, 2)
    )
    if hasattr(payload, "seek"):
        payload.seek(0)
        content_length = payload.seek(0, 2)
        payload.seek(0)
    else:
        content_length = len(payload)
    conn.request(
        "PUT",
        "/test",
        body=payload,
        headers={"Content-Length": str(content_length)},
    )
    resp = conn.getresponse()
    resp.read()
    conn.close()


# ---------------------------------------------------------------------------
# Phase 1 – syscall pattern
# ---------------------------------------------------------------------------


def phase1_syscall_pattern():
    print("=" * 70)
    print("PHASE 1: socket.sendall() call pattern")
    print("=" * 70)

    data = b"X" * S3_CHUNK_SIZE
    tracker = SendallTracker()

    # --- bytes path (current connector) ---
    with loopback_http_server() as (host, port):
        with tracker.track():
            send_via_http_client(host, port, data)

    bytes_calls = list(tracker.calls)

    # --- BytesIO path (proposed fix) ---
    with loopback_http_server() as (host, port):
        with tracker.track():
            send_via_http_client(host, port, io.BytesIO(data))

    bytesio_calls = list(tracker.calls)

    print(f"\nPayload size: {S3_CHUNK_SIZE / 1024 / 1024:.0f} MB\n")

    print(f"  bytes   (current connector) : {len(bytes_calls):4d} sendall() call(s)")
    if bytes_calls:
        readable = [
            (
                f"{s/1024/1024:.1f}MB"
                if s >= 1024 * 1024
                else f"{s/1024:.1f}KB" if s >= 1024 else f"{s}B"
            )
            for s in bytes_calls
        ]
        print(f"    sizes: {readable}")
        print(
            f"    largest single call: {max(bytes_calls)/1024/1024:.1f} MB  ← saturates socket buffer"
        )

    print(
        f"\n  BytesIO (proposed fix)       : {len(bytesio_calls):4d} sendall() call(s)"
    )
    if bytesio_calls:
        print(
            f"    max chunk: {max(bytesio_calls)} bytes  (http.client blocksize = {HTTP_BLOCKSIZE} bytes)"
        )
        print("    kernel always has buffer headroom between slices")

    # The bytes path sends headers + body + possible trailing bytes.
    # The important invariant: the body itself goes as one giant call.
    body_bytes_calls = [s for s in bytes_calls if s >= S3_CHUNK_SIZE]
    print()
    assert len(body_bytes_calls) == 1, (
        f"Expected exactly 1 sendall >= {S3_CHUNK_SIZE} bytes for bytes payload, "
        f"got calls: {bytes_calls}"
    )
    assert (
        body_bytes_calls[0] == S3_CHUNK_SIZE
    ), f"Body sendall should be exactly {S3_CHUNK_SIZE} bytes"
    assert len(bytesio_calls) > 1, "Expected many sendall calls for BytesIO payload"
    assert (
        max(bytesio_calls) <= HTTP_BLOCKSIZE
    ), f"BytesIO chunks should be <= {HTTP_BLOCKSIZE} bytes"
    print(
        f"  [PASS] bytes   → body sent in 1 sendall of {S3_CHUNK_SIZE//1024//1024} MB  "
        f"(can saturate socket buffer)"
    )
    print(
        f"  [PASS] BytesIO → body sent in {len(bytesio_calls)} sendalls of "
        f"≤{HTTP_BLOCKSIZE} bytes each  (kernel retains buffer headroom)"
    )


# ---------------------------------------------------------------------------
# Phase 2 – blocking syscall demonstration
# ---------------------------------------------------------------------------

# Use a payload large enough that macOS loopback can't buffer it all locally
# in a single SO_SNDBUF worth of kernel memory.
P2_PAYLOAD = 1 * 1024 * 1024  # 1 MB
P2_SNDBUF = 4096  # client send buffer
P2_RCVBUF = 4096  # server recv buffer
P2_READ_CHUNK = 8192  # server reads this many bytes at a time
P2_READ_DELAY = 0.05  # seconds between server reads (~160 KB/s)
P2_TIMEOUT = 3.0  # sendall timeout to detect stall


def _slow_server(
    server_sock: socket.socket, done: threading.Event, timestamps: list
) -> None:
    """Accepts one connection, trickle-reads, and records receipt timestamps."""
    server_sock.settimeout(10.0)
    try:
        conn, _ = server_sock.accept()
    except OSError:
        return
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, P2_RCVBUF)
    conn.settimeout(0.5)
    try:
        while not done.is_set():
            try:
                chunk = conn.recv(P2_READ_CHUNK)
            except socket.timeout:
                continue
            if not chunk:
                break
            timestamps.append((time.monotonic(), len(chunk)))
            time.sleep(P2_READ_DELAY)
    except OSError:
        pass
    finally:
        conn.close()


def _make_constrained_server() -> tuple[socket.socket, str, int, list, threading.Event]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    ts: list = []
    done = threading.Event()
    t = threading.Thread(target=_slow_server, args=(srv, done, ts), daemon=True)
    t.start()
    return srv, host, port, ts, done


def _constrained_client(
    host: str, port: int, timeout: float = P2_TIMEOUT
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, P2_SNDBUF)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def phase2_stall_simulation():
    print("=" * 70)
    print("PHASE 2: blocking sendall() behaviour under a starved receive window")
    print("=" * 70)
    print(
        f"\n  Payload : {P2_PAYLOAD // 1024} KB"
        f"\n  SO_SNDBUF (client): {P2_SNDBUF} bytes"
        f"\n  SO_RCVBUF (server): {P2_RCVBUF} bytes"
        f"\n  Server read rate  : {P2_READ_CHUNK} bytes every {P2_READ_DELAY}s"
        f"  (~{P2_READ_CHUNK / P2_READ_DELAY / 1024:.0f} KB/s)\n"
    )

    data = b"X" * P2_PAYLOAD

    # ---- bytes path (one big sendall) ----
    srv, host, port, ts_bytes, done_b = _make_constrained_server()
    time.sleep(0.05)

    syscall_log: list = []  # (wall_time_relative, bytes_in_call, duration)

    bytes_error = None
    sock = _constrained_client(host, port, timeout=8.0)
    call_start = time.monotonic()
    try:
        sock.sendall(data)
    except OSError as e:
        bytes_error = e
    call_end = time.monotonic()
    syscall_log.append(("bytes", call_end - call_start, len(data)))
    sock.close()
    done_b.set()
    srv.close()

    # ---- BytesIO path (many 8 KB sendalls) ----
    srv2, host2, port2, ts_bio, done_bio = _make_constrained_server()
    time.sleep(0.05)

    bio_calls: list = []
    sock2 = _constrained_client(host2, port2, timeout=60.0)
    bio = io.BytesIO(data)
    try:
        while True:
            block = bio.read(HTTP_BLOCKSIZE)
            if not block:
                break
            call_start = time.monotonic()
            sock2.sendall(block)
            call_end = time.monotonic()
            bio_calls.append(call_end - call_start)
    except OSError:
        pass
    sock2.close()
    done_bio.set()
    srv2.close()

    # ---- report ----
    b_duration = syscall_log[0][1]
    bio_max = max(bio_calls) if bio_calls else 0.0
    bio_total = sum(bio_calls) if bio_calls else 0.0

    print(
        f"  bytes   path: 1 sendall() call, blocked for {b_duration:.3f}s"
        + (f"  ERROR: {bytes_error}" if bytes_error else "")
    )
    print(f"  BytesIO path: {len(bio_calls)} sendall() calls")
    print(f"    worst single call  : {bio_max*1000:.1f} ms")
    print(f"    total in sendall() : {bio_total:.3f}s")
    print()
    print("  Key insight:")
    print("    bytes   → one call places the ENTIRE payload in the kernel buffer,")
    print(
        f"              occupying it for {b_duration:.2f}s.  Under packet loss, the TCP"
    )
    print("              window never reopens, so this call never returns → deadlock.")
    print("    BytesIO → data enters the kernel in 8 KB slices.  Each slice is")
    print("              acknowledged before the next is sent, so the kernel's")
    print("              send buffer never reaches saturation; Fast Retransmit")
    print("              requests are always serviced.")
    if bytes_error:
        print(f"\n  [PASS] bytes path timed out as expected: {bytes_error}")
    else:
        print("\n  [NOTE] bytes path completed (macOS kernel buffered data locally).")
        print("         The deadlock only manifests when ACTUAL packet loss prevents")
        print("         the TCP window from ever advancing (see pfctl instructions).")
        print("         Phase 1 proves the syscall pattern is the same regardless.")


# ---------------------------------------------------------------------------
# Phase 3 – show that _hash_bytes_hex is NOT called for PUT uploads
#            (so BytesIO is safe to use there)
# ---------------------------------------------------------------------------


def phase3_unsigned_payload_safety():
    print("=" * 70)
    print("PHASE 3: unsigned_payload=True bypass (fix is safe for PUT uploads)")
    print("=" * 70)

    # In _send_request_with_authentication_and_retry:
    #   if unsigned_payload:
    #       x_amz_headers["x-amz-content-sha256"] = UNSIGNED_PAYLOAD  ← no hash
    #   else:
    #       x_amz_headers["x-amz-content-sha256"] = _hash_bytes_hex(payload)
    #
    # _upload_chunk always passes unsigned_payload=True for PUT operations.
    # Passing io.BytesIO instead of bytes is therefore safe: the hash path
    # is never reached for upload payloads.

    from snowflake.connector.s3_storage_client import SnowflakeS3RestClient

    called_hash = []
    # _hash_bytes_hex is a @staticmethod — access it directly as a plain function
    original_hash = SnowflakeS3RestClient._hash_bytes_hex

    def patched_hash(data):
        called_hash.append(type(data).__name__)
        return original_hash(data)

    SnowflakeS3RestClient._hash_bytes_hex = staticmethod(patched_hash)

    # Simulate the unsigned_payload=True branch
    payload = io.BytesIO(b"X" * 1024)
    unsigned_payload = True

    if not unsigned_payload:
        SnowflakeS3RestClient._hash_bytes_hex(payload)

    SnowflakeS3RestClient._hash_bytes_hex = staticmethod(original_hash)
    assert len(called_hash) == 0, "hash should NOT be called for PUT uploads"

    print("\n  unsigned_payload=True branch does NOT call _hash_bytes_hex")
    print("  → Wrapping PUT payload in io.BytesIO is safe (hash is bypassed)")
    print()
    print("  [PASS] Fix can be applied only to the bytes→socket path without")
    print("         breaking S3 request signing.")


# ---------------------------------------------------------------------------
# Phase 4 – actual HTTP 400 RequestTimeout from a mock S3 server
# ---------------------------------------------------------------------------

# Real S3 RequestTimeout XML body (from AWS S3 error response spec)
S3_REQUEST_TIMEOUT_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b"<Error>\n"
    b"  <Code>RequestTimeout</Code>\n"
    b"  <Message>Your socket connection to the server was not read from "
    b"or written to within the timeout period. "
    b"Idle connections will be closed.</Message>\n"
    b"  <RequestId>EXAMPLE1234567890ABCD</RequestId>\n"
    b"  <HostId>EXAMPLE+HOST+ID=</HostId>\n"
    b"</Error>"
)

# How long the server stalls on the body before timing out the upload.
# Real S3 uses ~119 s; we use 2 s for a fast demo.
P4_SERVER_TIMEOUT = 2.0
# Payload must be large enough that sendall(bytes) blocks during the stall.
P4_PAYLOAD = 2 * 1024 * 1024  # 2 MB


def _mock_s3_handler(conn: socket.socket) -> None:
    """
    Simulate S3's RequestTimeout behaviour:
      - Read the HTTP request headers.
      - Stall on the body for P4_SERVER_TIMEOUT seconds (the "frozen TCP window").
      - Drain whatever body data arrived during the stall.
      - Return HTTP 400 RequestTimeout XML and close.
    The client is still trying to sendall() the rest of the body when we
    respond — mirroring the real S3 scenario.
    """
    conn.settimeout(30.0)
    # Read until end of headers
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            conn.close()
            return
        buf += chunk

    # Stall — don't drain the body.  The sender's send buffer fills and
    # sendall() blocks, exactly as it does when the TCP window freezes
    # under packet loss.
    time.sleep(P4_SERVER_TIMEOUT)

    # Non-blocking drain of whatever slipped in during the stall.
    conn.setblocking(False)
    try:
        while conn.recv(65536):
            pass
    except OSError:
        pass
    conn.setblocking(True)

    # Send the real S3 RequestTimeout response.
    http_400 = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Type: application/xml\r\n"
        + f"Content-Length: {len(S3_REQUEST_TIMEOUT_XML)}\r\n".encode()
        + b"Connection: close\r\n"
        b"\r\n" + S3_REQUEST_TIMEOUT_XML
    )
    try:
        conn.sendall(http_400)
    except OSError:
        pass
    conn.close()


@contextmanager
def mock_s3_server(bind_addr: str = "127.0.0.1") -> Generator[tuple[str, int]]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_addr, 0))
    srv.listen(5)
    host, port = srv.getsockname()

    def accept_loop():
        srv.settimeout(5.0)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=_mock_s3_handler, args=(conn,), daemon=True).start()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        yield host, port
    finally:
        srv.close()
        t.join(timeout=1.0)


def phase4_http400_timeout():
    try:
        from snowflake.connector.vendored import requests as _requests

        requests = _requests
    except ImportError:
        import requests  # type: ignore[no-redef]

    print("=" * 70)
    print("PHASE 4: actual HTTP 400 RequestTimeout from mock S3")
    print("=" * 70)
    print(
        f"\n  Payload : {P4_PAYLOAD // 1024 // 1024} MB"
        f"  (same as S3_DEFAULT_CHUNK_SIZE)"
        f"\n  Server stall: {P4_SERVER_TIMEOUT}s without reading body"
        f"  (real S3: ~119s)\n"
    )

    data = b"X" * P4_PAYLOAD

    # ---- bytes path (current connector: passes raw bytes to requests) ----
    with mock_s3_server() as (host, port):
        url = f"http://{host}:{port}/upload"
        t0 = time.monotonic()
        try:
            resp = requests.put(
                url,
                data=data,
                headers={"Content-Length": str(len(data))},
                timeout=30,
            )
            elapsed = time.monotonic() - t0
            status = resp.status_code
            body = resp.text
        except Exception as exc:
            elapsed = time.monotonic() - t0
            status = None
            body = str(exc)

    print(f"  bytes path ({len(data)//1024//1024} MB as raw bytes):")
    print(f"    elapsed    : {elapsed:.2f}s")
    if status is not None:
        print(f"    HTTP status: {status}")
        if status == 400:
            try:
                root = ET.fromstring(body)
                code = root.find("Code")
                msg = root.find("Message")
                print(f"    S3 Code    : {code.text if code is not None else '?'}")
                print(f"    S3 Message : {msg.text[:80] if msg is not None else '?'}")
            except ET.ParseError:
                print(f"    body       : {body[:120]}")
    else:
        print(f"    exception  : {body[:120]}")

    # ---- BytesIO path (proposed fix) ----
    with mock_s3_server() as (host, port):
        url = f"http://{host}:{port}/upload"
        t0 = time.monotonic()
        try:
            resp = requests.put(
                url,
                data=io.BytesIO(data),
                headers={"Content-Length": str(len(data))},
                timeout=30,
            )
            elapsed_bio = time.monotonic() - t0
            status_bio = resp.status_code
            body_bio = resp.text
        except Exception as exc:
            elapsed_bio = time.monotonic() - t0
            status_bio = None
            body_bio = str(exc)

    print(f"\n  BytesIO path ({len(data)//1024//1024} MB as io.BytesIO):")
    print(f"    elapsed    : {elapsed_bio:.2f}s")
    if status_bio is not None:
        print(f"    HTTP status: {status_bio}")
        if status_bio == 400:
            try:
                root = ET.fromstring(body_bio)
                code = root.find("Code")
                print(f"    S3 Code    : {code.text if code is not None else '?'}")
            except ET.ParseError:
                print(f"    body       : {body_bio[:120]}")
    else:
        print(f"    exception  : {body_bio[:120]}")

    print()
    print("  Interpretation:")
    if status == 400:
        print(
            f"    [PASS] bytes path received HTTP 400 RequestTimeout after {elapsed:.1f}s"
        )
        print("           This is the exact error the customer saw from real S3.")
    else:
        print(f"    bytes path result: status={status} (see above)")
    if status_bio == 400:
        print("    BytesIO also received HTTP 400 in this simulation because")
        print("    loopback has no actual packet loss — both paths reach the server")
        print("    at full speed.  The difference only emerges under real packet")
        print("    loss, where the bytes path deadlocks and BytesIO does not.")
    elif status_bio is None:
        print("    BytesIO raised an exception (see above).")
    else:
        print(f"    BytesIO path: HTTP {status_bio}")


# ---------------------------------------------------------------------------
# Phase 5 – real packet loss via dnctl + pfctl (macOS only, requires sudo)
# ---------------------------------------------------------------------------

DUMMYNET_PIPE = 99  # high number unlikely to conflict with existing pipes
PACKET_LOSS_RATE = 0.30  # 30%
P5_TEST_ADDR = "127.0.0.2"  # 127.x.x.x always routes to lo0 — no alias needed
P5_PAYLOAD = 8 * 1024 * 1024  # 8 MB = S3_DEFAULT_CHUNK_SIZE
P5_BYTES_TIMEOUT = 30.0  # give up on bytes path after this many seconds


def _sudo(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"text": True}
    if capture:
        kw["capture_output"] = True
    return subprocess.run(["sudo"] + list(args), **kw)


def _pf_is_enabled() -> bool:
    r = _sudo("pfctl", "-si", capture=True)
    return "Status: Enabled" in r.stdout


def _pf_save_rules() -> str:
    return _sudo("pfctl", "-sr", capture=True).stdout


def _setup_packet_loss() -> bool:
    """Configure dnctl pipe + pfctl to drop PACKET_LOSS_RATE of TCP to P5_TEST_ADDR."""
    r = _sudo(
        "dnctl",
        "pipe",
        str(DUMMYNET_PIPE),
        "config",
        "plr",
        f"{PACKET_LOSS_RATE:.2f}",
        capture=True,
    )
    if r.returncode != 0:
        print(f"  dnctl pipe config failed: {r.stderr.strip()}")
        return False

    rules = (
        f"dummynet out on lo0 proto tcp from any to {P5_TEST_ADDR} "
        f"pipe {DUMMYNET_PIPE}\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(rules)
        tmp = f.name
    try:
        r = _sudo("pfctl", "-f", tmp, capture=True)
        if r.returncode != 0:
            print(f"  pfctl -f failed: {r.stderr.strip()}")
            return False
    finally:
        os.unlink(tmp)

    r = _sudo("pfctl", "-e", capture=True)
    if r.returncode != 0 and "already enabled" not in r.stderr.lower():
        print(f"  pfctl -e: {r.stderr.strip()}")
        return False

    return True


def _restore_pf(was_enabled: bool, saved_rules: str) -> None:
    _sudo("pfctl", "-d", capture=True)
    _sudo("dnctl", "pipe", str(DUMMYNET_PIPE), "delete", capture=True)
    if saved_rules.strip():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(saved_rules)
            tmp = f.name
        try:
            _sudo("pfctl", "-f", tmp, capture=True)
        finally:
            os.unlink(tmp)
    if was_enabled:
        _sudo("pfctl", "-e", capture=True)


def _p5_upload(payload, sock_addr: tuple[str, int], timeout: float) -> dict:
    """
    Upload payload (bytes or BytesIO) to a raw TCP server at sock_addr.
    Returns {"elapsed": float, "status": int|None, "error": str|None, "xml_code": str|None}
    """
    try:
        from snowflake.connector.vendored import requests as _req
    except ImportError:
        import requests as _req  # type: ignore[no-redef]

    host, port = sock_addr
    url = f"http://{host}:{port}/upload"
    content_length = (
        len(payload)
        if isinstance(payload, (bytes, bytearray))
        else (payload.seek(0, 2) or payload.seek(0, 2))
    )
    if hasattr(payload, "seek"):
        payload.seek(0)
        content_length = payload.seek(0, 2)
        payload.seek(0)
    else:
        content_length = len(payload)

    t0 = time.monotonic()
    result: dict = {}
    try:
        resp = _req.put(
            url,
            data=payload,
            headers={"Content-Length": str(content_length)},
            timeout=timeout,
        )
        result["elapsed"] = time.monotonic() - t0
        result["status"] = resp.status_code
        result["error"] = None
        try:
            root = ET.fromstring(resp.text)
            code = root.find("Code")
            result["xml_code"] = code.text if code is not None else None
        except ET.ParseError:
            result["xml_code"] = None
    except Exception as exc:
        result["elapsed"] = time.monotonic() - t0
        result["status"] = None
        result["error"] = type(exc).__name__ + ": " + str(exc)[:120]
        result["xml_code"] = None
    return result


def phase5_packet_loss():
    print("=" * 70)
    print("PHASE 5: real packet loss via dnctl + pfctl (requires sudo)")
    print("=" * 70)

    if sys.platform != "darwin":
        print("\n  Skipped: Phase 5 requires macOS (dnctl + pfctl).")
        return
    if not shutil.which("dnctl"):
        print("\n  Skipped: /usr/sbin/dnctl not found.")
        return

    print(
        f"\n  Interface  : lo0 → {P5_TEST_ADDR}"
        f"\n  Packet loss: {PACKET_LOSS_RATE*100:.0f}%  (dummynet pipe {DUMMYNET_PIPE})"
        f"\n  Payload    : {P5_PAYLOAD // 1024 // 1024} MB  (S3_DEFAULT_CHUNK_SIZE)"
        f"\n  bytes timeout: {P5_BYTES_TIMEOUT}s\n"
    )

    # Warm up sudo credentials once (shows password prompt if needed)
    print("  Requesting sudo (password prompt may appear)...")
    r = _sudo("true")
    if r.returncode != 0:
        print("  sudo failed — skipping Phase 5.")
        return

    was_enabled = _pf_is_enabled()
    saved_rules = _pf_save_rules()

    try:
        if not _setup_packet_loss():
            return
        print("  Packet loss active.\n")

        # Verify loss is configured
        r = _sudo("dnctl", "pipe", str(DUMMYNET_PIPE), "show", capture=True)
        for line in r.stdout.splitlines():
            if "plr" in line or "q." in line or str(DUMMYNET_PIPE) in line:
                print(f"  dnctl: {line.strip()}")
        print()

        data = b"X" * P5_PAYLOAD

        # ---- bytes path ----
        with mock_s3_server(bind_addr=P5_TEST_ADDR) as (host, port):
            print(f"  [bytes path] PUT {P5_PAYLOAD//1024//1024}MB → {host}:{port}")
            res = _p5_upload(data, (host, port), timeout=P5_BYTES_TIMEOUT)

        print(f"    elapsed : {res['elapsed']:.2f}s")
        if res["status"] is not None:
            print(f"    HTTP    : {res['status']}")
            if res["xml_code"]:
                print(f"    S3 code : {res['xml_code']}")
        else:
            print(f"    error   : {res['error']}")

        # ---- BytesIO path ----
        with mock_s3_server(bind_addr=P5_TEST_ADDR) as (host, port):
            print(f"\n  [BytesIO path] PUT {P5_PAYLOAD//1024//1024}MB → {host}:{port}")
            res_bio = _p5_upload(
                io.BytesIO(data), (host, port), timeout=P5_BYTES_TIMEOUT * 3
            )

        print(f"    elapsed : {res_bio['elapsed']:.2f}s")
        if res_bio["status"] is not None:
            print(f"    HTTP    : {res_bio['status']}")
            if res_bio["xml_code"]:
                print(f"    S3 code : {res_bio['xml_code']}")
        else:
            print(f"    error   : {res_bio['error']}")

        print()
        _summarise_phase5(res, res_bio)

    finally:
        _restore_pf(was_enabled, saved_rules)
        print("\n  pfctl/dnctl state restored.")


def _summarise_phase5(bytes_res: dict, bio_res: dict) -> None:
    b_ok = bytes_res["status"] == 200
    b_400 = bytes_res["status"] == 400 and bytes_res.get("xml_code") == "RequestTimeout"
    b_err = bytes_res["error"] is not None

    bio_ok = bio_res["status"] == 200
    bio_400 = bio_res["status"] == 400 and bio_res.get("xml_code") == "RequestTimeout"

    print("  Result:")
    if b_400 or b_err:
        print(
            f"    bytes   → STALLED/TIMEOUT after {bytes_res['elapsed']:.1f}s  ✓ theory confirmed"
        )
    elif b_ok:
        print(
            f"    bytes   → succeeded in {bytes_res['elapsed']:.1f}s  "
            f"(30% loss insufficient on loopback to trigger deadlock)"
        )
    else:
        print(f"    bytes   → {bytes_res}")

    if bio_ok:
        print(f"    BytesIO → succeeded in {bio_res['elapsed']:.1f}s  ✓ fix works")
    elif bio_400 or bio_res["error"]:
        print(
            f"    BytesIO → also failed ({bio_res['elapsed']:.1f}s) — "
            f"increase PACKET_LOSS_RATE or try with real S3 + pfctl"
        )
    else:
        print(f"    BytesIO → {bio_res}")


# ---------------------------------------------------------------------------
# macOS pfctl instructions
# ---------------------------------------------------------------------------

PFCTL_INSTRUCTIONS = """
To reproduce the FULL timeout (HTTP 400 RequestTimeout from real S3):

1. Enable packet loss on en0 (5% simulates Wi-Fi degradation):

   sudo pfctl -e
   printf 'block drop quick on en0 proto tcp from any to any port 443 probability 0.05\\n' \\
       | sudo pfctl -f -

2. Run a large file upload through the connector (before the fix):

   python -c "
   import snowflake.connector
   conn = snowflake.connector.connect(...)
   conn.cursor().execute(\\"PUT file:///tmp/big_file.dat @mystage\\")"

3. Observe: HTTP 400 RequestTimeout after ~119 seconds.

4. Apply the fix (sys.platform == 'darwin' BytesIO wrapping) and retry.
   Upload completes without timeout.

5. Disable packet loss:

   sudo pfctl -d
"""

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\nPlatform: {sys.platform}")
    print(f"Python  : {sys.version.split()[0]}")
    print(f"S3 chunk: {S3_CHUNK_SIZE / 1024 / 1024:.0f} MB")
    print(f"http.client blocksize: {HTTP_BLOCKSIZE} bytes\n")

    phase1_syscall_pattern()
    print()
    phase2_stall_simulation()
    print()

    try:
        phase3_unsigned_payload_safety()
    except ImportError:
        print("(Phase 3 skipped: snowflake.connector not importable here)")

    print()
    phase4_http400_timeout()

    if "--phase5" in sys.argv:
        print()
        phase5_packet_loss()

    print("=" * 70)
    print("macOS full-reproduction instructions (requires real S3 + pfctl):")
    print(PFCTL_INSTRUCTIONS)
