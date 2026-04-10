"""MitmClient for managing mitmproxy instances in tests."""

import logging
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

MITM_START_MAX_WAIT_SECONDS = 30
MITM_PORT_DETECTION_MAX_WAIT_SECONDS = 10


class MitmClient:
    """Client for managing a mitmproxy instance for testing.

    This class handles:
    - Starting/stopping mitmdump process
    - Port detection via addon
    - CA certificate management
    - Process lifecycle

    Usage:
        with MitmClient() as client:
            print(f"Proxy running at {client.proxy_url}")
            # Use client.host, client.port, client.ca_cert_path
    """

    def __init__(self):
        self.mitm_host = "127.0.0.1"
        self.mitm_port = None
        self.mitm_process = None
        self.ca_cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

        # Get path to the addon script
        self.addon_script_path = Path(__file__).parent / "port_detector_addon.py"
        if not self.addon_script_path.exists():
            raise RuntimeError(
                f"Port detector addon not found at {self.addon_script_path}"
            )

        # Create temp file for port communication
        self.port_file = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt", prefix="mitm_port_"
        )
        self.port_file.close()
        self.port_file_path = self.port_file.name

    @property
    def host(self) -> str:
        """Proxy host address."""
        return self.mitm_host

    @property
    def port(self) -> int:
        """Proxy port number."""
        if self.mitm_port is None:
            raise RuntimeError("Proxy port not yet detected. Call _start_mitm() first.")
        return self.mitm_port

    @property
    def proxy_url(self) -> str:
        """Full proxy URL."""
        return f"http://{self.host}:{self.port}"

    def set_env_vars(self, monkeypatch):
        """Set proxy environment variables for testing.

        Args:
            monkeypatch: pytest monkeypatch fixture
        """
        monkeypatch.setenv("HTTP_PROXY", self.proxy_url)
        monkeypatch.setenv("HTTPS_PROXY", self.proxy_url)
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(self.ca_cert_path))
        monkeypatch.setenv("CURL_CA_BUNDLE", str(self.ca_cert_path))
        monkeypatch.setenv("SSL_CERT_FILE", str(self.ca_cert_path))

    def _check_mitmdump_available(self):
        """Check if mitmdump is installed and available."""
        logger.debug("Checking if mitmdump is installed...")
        try:
            subprocess.run(
                ["mitmdump", "--version"],
                capture_output=True,
                check=True,
                timeout=5,
            )
            logger.debug("mitmdump is installed and available")
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ) as e:
            logger.error(f"mitmdump check failed: {e}")
            raise RuntimeError(
                "mitmproxy (mitmdump) is not installed. Install with: pip install mitmproxy"
            ) from e

    def _start_mitm(self):
        """Start the mitmproxy process."""
        self._check_mitmdump_available()

        logger.debug(f"Port will be written to: {self.port_file_path}")
        logger.debug(
            f"Starting mitmdump process on {self.mitm_host}:0 (auto-assign port)..."
        )

        # Set environment variable for the addon
        env = os.environ.copy()
        env["MITM_PORT_FILE"] = self.port_file_path

        self.mitm_process = subprocess.Popen(
            [
                "mitmdump",
                "--listen-host",
                self.mitm_host,
                "--listen-port",
                "0",  # OS will assign a free port
                "--set",
                "connection_strategy=lazy",  # Don't connect to upstream unless needed
                "--set",
                "stream_large_bodies=1m",  # Stream large bodies
                "-s",
                str(self.addon_script_path),  # Load our port detector addon
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        logger.debug(f"mitmdump process started with PID {self.mitm_process.pid}")

        # Wait for CA certificate generation
        self._wait_for_ca_cert()

        # Wait for port detection
        self._wait_for_port()

        # Verify proxy is accepting connections
        self._verify_proxy_listening()

        logger.info(f"mitmproxy ready at {self.proxy_url}")

    def _wait_for_ca_cert(self):
        """Wait for mitmproxy to generate its CA certificate."""
        logger.debug(f"Waiting for CA certificate at: {self.ca_cert_path}")
        start_time = time.time()

        while not self.ca_cert_path.exists():
            elapsed = time.time() - start_time

            if elapsed > MITM_START_MAX_WAIT_SECONDS:
                logger.error(
                    f"Timeout waiting for CA certificate after {MITM_START_MAX_WAIT_SECONDS}s"
                )
                self._cleanup_on_error()
                raise TimeoutError(
                    f"mitmproxy CA certificate not generated after {MITM_START_MAX_WAIT_SECONDS}s"
                )

            if self.mitm_process.poll() is not None:
                logger.error("mitmdump process died during CA cert generation")
                stdout, stderr = self.mitm_process.communicate()
                self._cleanup_on_error()
                raise RuntimeError(
                    f"mitmproxy process died during startup.\nStdout: {stdout}\nStderr: {stderr}"
                )

            time.sleep(0.5)

        logger.debug(f"CA certificate found at {self.ca_cert_path}")

    def _wait_for_port(self):
        """Wait for the addon to write the port to the file."""
        logger.debug("Waiting for addon to write port to file...")
        start_time = time.time()

        while self.mitm_port is None:
            elapsed = time.time() - start_time

            if elapsed > MITM_PORT_DETECTION_MAX_WAIT_SECONDS:
                logger.error(
                    f"Timeout waiting for port file after {MITM_PORT_DETECTION_MAX_WAIT_SECONDS}s"
                )
                logger.error(f"Port file path: {self.port_file_path}")
                logger.error(f"Port file exists: {Path(self.port_file_path).exists()}")
                self._cleanup_on_error()
                raise TimeoutError("Could not determine mitmproxy port from addon")

            if self.mitm_process.poll() is not None:
                logger.error("mitmdump process died during port detection")
                stdout, stderr = self.mitm_process.communicate()
                self._cleanup_on_error()
                raise RuntimeError(
                    f"mitmproxy died before port detection.\nStdout: {stdout}\nStderr: {stderr}"
                )

            # Check if port file has been written
            if Path(self.port_file_path).exists():
                try:
                    with open(self.port_file_path) as f:
                        port_str = f.read().strip()
                        if port_str:
                            self.mitm_port = int(port_str)
                            logger.debug(f"Port detected from file: {self.mitm_port}")
                            break
                except (ValueError, OSError) as e:
                    logger.warning(f"Error reading port file: {e}")

            time.sleep(0.1)

        logger.debug(f"Successfully detected port {self.mitm_port}")

    def _verify_proxy_listening(self):
        """Verify that the proxy is accepting connections."""
        logger.debug(
            f"Verifying proxy is accepting connections on {self.mitm_host}:{self.mitm_port}..."
        )
        try:
            with socket.create_connection((self.mitm_host, self.mitm_port), timeout=5):
                pass
            logger.debug("Proxy is accepting connections!")
        except (socket.timeout, ConnectionRefusedError) as e:
            logger.error(f"Proxy not accepting connections: {e}")
            self._cleanup_on_error()
            raise RuntimeError(f"mitmproxy not accepting connections: {e}") from e

    def _cleanup_on_error(self):
        """Cleanup resources when an error occurs during startup."""
        if self.mitm_process:
            self.mitm_process.kill()
        self._cleanup_port_file()

    def _cleanup_port_file(self):
        """Remove the temporary port file."""
        try:
            os.unlink(self.port_file_path)
            logger.debug("Cleaned up port file")
        except OSError:
            pass

    def _stop_mitm(self):
        """Stop the mitmproxy process."""
        if self.mitm_process is None:
            return

        if self.mitm_process.poll() is not None:
            logger.warning("mitmproxy process already exited, skipping shutdown")
            return

        logger.debug("Stopping mitmproxy...")
        self.mitm_process.terminate()
        try:
            self.mitm_process.wait(timeout=5)
            logger.debug("mitmproxy stopped gracefully")
        except subprocess.TimeoutExpired:
            logger.debug("mitmproxy didn't stop gracefully, killing...")
            self.mitm_process.kill()
            self.mitm_process.wait()
            logger.debug("mitmproxy killed")

        self._cleanup_port_file()

    def __enter__(self):
        """Context manager entry."""
        self._start_mitm()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self._stop_mitm()
