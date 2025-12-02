import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

import pytest


@pytest.fixture
def proxy_env_vars():
    """Manages HTTP_PROXY and HTTPS_PROXY environment variables for testing."""
    original_http_proxy = os.environ.get("HTTP_PROXY")
    original_https_proxy = os.environ.get("HTTPS_PROXY")
    original_no_proxy = os.environ.get("NO_PROXY")

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
        if "NO_PROXY" in os.environ:
            del os.environ["NO_PROXY"]

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

    if original_no_proxy is not None:
        os.environ["NO_PROXY"] = original_no_proxy
    elif "NO_PROXY" in os.environ:
        del os.environ["NO_PROXY"]


class MitmProxyInfo(NamedTuple):
    """Information about a running mitmproxy instance.

    Use this to configure your connection or environment variables as needed.
    """

    host: str
    port: int
    ca_cert_path: Path
    proxy_url: str

    def set_env_vars(self, monkeypatch):
        """Helper to set proxy environment variables.

        Args:
            monkeypatch: pytest monkeypatch fixture
        """
        monkeypatch.setenv("HTTP_PROXY", self.proxy_url)
        monkeypatch.setenv("HTTPS_PROXY", self.proxy_url)
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(self.ca_cert_path))
        monkeypatch.setenv("CURL_CA_BUNDLE", str(self.ca_cert_path))
        monkeypatch.setenv("SSL_CERT_FILE", str(self.ca_cert_path))


@pytest.fixture(scope="session")
def mitm_proxy():
    """Start mitmproxy for transparent HTTPS proxying in tests.

    This fixture (session-scoped):
    - Starts mitmdump once for all tests
    - Waits for CA certificate generation
    - Returns proxy information (does NOT set env vars automatically)
    - Cleans up after all tests complete

    The fixture does NOT automatically configure proxy settings.
    Tests should explicitly use the proxy via:
    1. Environment variables: mitm_proxy.set_env_vars(monkeypatch)
    2. Connection parameters: conn_cnx(proxy_host=..., proxy_port=...)

    Yields:
        MitmProxyInfo: Information about the running proxy instance
    """
    print("\n[MITM] Starting mitmproxy fixture setup...")

    # Check if mitmproxy is available
    print("[MITM] Checking if mitmdump is installed...")
    try:
        subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True,
            check=True,
            timeout=5,
        )
        print("[MITM] mitmdump is installed and available")
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ) as e:
        print(f"[MITM] mitmdump check failed: {e}")
        pytest.fail(
            "mitmproxy (mitmdump) is not installed. Install with: pip install mitmproxy"
        )

    proxy_host = "127.0.0.1"

    # Create a temporary addon script to capture the assigned port
    # This is the recommended approach per mitmproxy maintainers:
    # https://github.com/mitmproxy/mitmproxy/discussions/6011
    port_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    port_file_path = port_file.name
    port_file.close()

    addon_script = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py")
    addon_script.write(
        f'''
from mitmproxy import ctx

def running():
    """Called when mitmproxy is fully started and ready."""
    # Get the actual port that was bound (when using --listen-port 0)
    # ctx.master.addons.get("proxyserver").listen_addrs() returns:
    # [('::', port, 0, 0), ('0.0.0.0', port)]
    addrs = ctx.master.addons.get("proxyserver").listen_addrs()
    if addrs:
        port = addrs[0][1]
        with open(r"{port_file_path}", "w") as f:
            f.write(str(port))
        ctx.log.info(f"Proxy listening on port {{port}}")
'''
    )
    addon_script.close()
    addon_script_path = addon_script.name
    print(f"[MITM] Created port detection addon: {addon_script_path}")
    print(f"[MITM] Port will be written to: {port_file_path}")

    # Start mitmdump with port 0 (let OS assign a free port) - thread-safe!
    print(f"[MITM] Starting mitmdump process on {proxy_host}:0 (auto-assign port)...")
    mitm_process = subprocess.Popen(
        [
            "mitmdump",
            "--listen-host",
            proxy_host,
            "--listen-port",
            "0",  # OS will assign a free port
            "--set",
            "connection_strategy=lazy",  # Don't connect to upstream unless needed
            "--set",
            "stream_large_bodies=1m",  # Stream large bodies
            "-s",
            addon_script_path,  # Load our addon to capture the port
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(f"[MITM] mitmdump process started with PID {mitm_process.pid}")

    # Wait for mitmproxy to generate CA certificate
    ca_cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    print(f"[MITM] Waiting for CA certificate at: {ca_cert_path}")
    max_wait_seconds = 30
    start_time = time.time()

    cert_wait_count = 0
    while not ca_cert_path.exists():
        cert_wait_count += 1
        elapsed = time.time() - start_time

        if cert_wait_count % 4 == 0:  # Print every 2 seconds
            print(f"[MITM] Still waiting for CA cert... ({elapsed:.1f}s elapsed)")

        if elapsed > max_wait_seconds:
            print(
                f"[MITM] Timeout waiting for CA certificate after {max_wait_seconds}s"
            )
            mitm_process.kill()
            pytest.fail(
                f"mitmproxy CA certificate not generated after {max_wait_seconds}s"
            )

        if mitm_process.poll() is not None:
            # Process died
            print("[MITM] ERROR: mitmdump process died during CA cert generation")
            stdout, stderr = mitm_process.communicate()
            pytest.fail(
                f"mitmproxy process died during startup.\nStdout: {stdout}\nStderr: {stderr}"
            )

        time.sleep(0.5)

    print(f"[MITM] CA certificate found at {ca_cert_path}")

    # Wait for the addon to write the port to the file
    print("[MITM] Waiting for addon to write port to file...")
    proxy_port = None
    max_port_wait = 10
    port_start_time = time.time()

    while proxy_port is None:
        elapsed = time.time() - port_start_time

        if elapsed > max_port_wait:
            print(f"[MITM] Timeout waiting for port file after {max_port_wait}s")
            print(f"[MITM] Port file path: {port_file_path}")
            print(f"[MITM] Port file exists: {Path(port_file_path).exists()}")
            mitm_process.kill()
            # Cleanup temp files
            try:
                os.unlink(port_file_path)
                os.unlink(addon_script_path)
            except OSError:
                pass
            pytest.fail("Could not determine mitmproxy port from addon")

        if mitm_process.poll() is not None:
            print("[MITM] ERROR: mitmdump process died during port detection")
            stdout, stderr = mitm_process.communicate()
            # Cleanup temp files
            try:
                os.unlink(port_file_path)
                os.unlink(addon_script_path)
            except OSError:
                pass
            pytest.fail(
                f"mitmproxy died before port detection.\nStdout: {stdout}\nStderr: {stderr}"
            )

        # Check if port file has been written
        if Path(port_file_path).exists():
            try:
                with open(port_file_path) as f:
                    port_str = f.read().strip()
                    if port_str:
                        proxy_port = int(port_str)
                        print(f"[MITM] Port detected from file: {proxy_port}")
                        break
            except (ValueError, OSError) as e:
                print(f"[MITM] Error reading port file: {e}")

        time.sleep(0.1)

    print(f"[MITM] Successfully detected port {proxy_port}")

    # Cleanup temp files
    try:
        os.unlink(port_file_path)
        os.unlink(addon_script_path)
        print("[MITM] Cleaned up temporary addon files")
    except Exception as e:
        print(f"[MITM] Warning: Could not cleanup temp files: {e}")

    proxy_url = f"http://{proxy_host}:{proxy_port}"
    print(f"[MITM] Proxy URL: {proxy_url}")

    # Verify proxy is listening
    print(
        f"[MITM] Verifying proxy is accepting connections on {proxy_host}:{proxy_port}..."
    )
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=5):
            pass
        print("[MITM] Proxy is accepting connections!")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"[MITM] ERROR: Proxy not accepting connections: {e}")
        mitm_process.kill()
        pytest.fail(f"mitmproxy not accepting connections: {e}")

    proxy_info = MitmProxyInfo(
        host=proxy_host,
        port=proxy_port,
        ca_cert_path=ca_cert_path,
        proxy_url=proxy_url,
    )

    print(f"[MITM] Setup complete! Proxy ready at {proxy_url}")
    print(f"[MITM] CA cert: {ca_cert_path}")

    try:
        yield proxy_info
    finally:
        # Cleanup: stop mitmproxy
        print("[MITM] Cleaning up: stopping mitmproxy...")
        mitm_process.terminate()
        try:
            mitm_process.wait(timeout=5)
            print("[MITM] mitmproxy stopped gracefully")
        except subprocess.TimeoutExpired:
            print("[MITM] mitmproxy didn't stop gracefully, killing...")
            mitm_process.kill()
            mitm_process.wait()
            print("[MITM] mitmproxy killed")
