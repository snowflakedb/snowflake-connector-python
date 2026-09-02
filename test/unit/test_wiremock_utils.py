"""Unit tests for the Wiremock harness itself.

These cover the port discovery and startup-failure reporting that replaced the
old "find a free port in Python, then hand it to java" approach, which could
race with any other process taking the port before the JVM bound it.

They are deliberately hermetic: no java process and no Wiremock jar is needed.
"""

from __future__ import annotations

import pathlib

import pytest

from ..test_utils.wiremock.wiremock_utils import (
    WIREMOCK_START_TIMEOUT_SECONDS,
    WiremockClient,
    _parse_wiremock_ports,
)

# A realistic Wiremock 3.11.0 startup banner, printed once the listeners are
# bound. The leading art contains ANSI escapes, which must not disturb parsing.
BANNER = """
\033[34m██     ██ ██ ██████  ███████ \033[33m███    ███  ██████   ██████ ██   ██
\033[0m----------------------------------------------------------------
|               Cloud: https://wiremock.io/cloud               |
----------------------------------------------------------------

version:                      3.11.0
port:                         45161
https-port:                   43329
https-keystore:               /repo/.wiremock/ca-cert.jks
enable-browser-proxying:      true
disable-banner:               false

extensions:                   response-template,webhook
"""


class _FakeProcess:
    """Stand-in for ``subprocess.Popen`` that never actually runs java."""

    def __init__(self, return_code: int | None) -> None:
        self._return_code = return_code

    def poll(self) -> int | None:
        return self._return_code


def _client_for_startup_checks(
    startup_output: str,
    return_code: int | None,
    tmp_path: pathlib.Path,
) -> WiremockClient:
    """Build a client around a canned startup log, bypassing ``__init__``.

    ``__init__`` asserts that the Wiremock jar is on disk, which these tests
    have no use for -- they only exercise the startup bookkeeping.
    """
    client = WiremockClient.__new__(WiremockClient)
    client.wiremock_host = "localhost"
    client.wiremock_http_port = 45161
    client.wiremock_https_port = None
    log_path = tmp_path / "wiremock-startup.log"
    log_path.write_text(startup_output)
    client._startup_log_path = log_path
    client.wiremock_process = _FakeProcess(return_code)
    return client


def test_parse_wiremock_ports_reads_both_ports_from_banner():
    assert _parse_wiremock_ports(BANNER) == (45161, 43329)


def test_parse_wiremock_ports_returns_none_before_banner_is_printed():
    assert _parse_wiremock_ports("") is None
    assert _parse_wiremock_ports("version:                      3.11.0\n") is None


def test_parse_wiremock_ports_does_not_mistake_https_port_for_http_port():
    """``https-port`` ends in ``port:`` -- it must not satisfy the http match."""
    assert _parse_wiremock_ports("https-port:                   43329\n") is None


def test_parse_wiremock_ports_allows_missing_https_port():
    assert _parse_wiremock_ports("port:                         45161\n") == (
        45161,
        None,
    )


def test_parse_wiremock_ports_ignores_a_bind_failure_without_ports():
    """A crashed startup must not be parsed as a successful one."""
    crash = (
        "com.github.tomakehurst.wiremock.common.FatalStartupException: "
        "java.io.IOException: Failed to bind to /0.0.0.0:33531\n"
    )
    assert _parse_wiremock_ports(crash) is None


def test_dead_process_is_reported_with_its_own_output(tmp_path):
    """A startup crash must surface java's message, not a bare timeout."""
    crash = (
        "com.github.tomakehurst.wiremock.common.FatalStartupException: "
        "java.io.IOException: Failed to bind to /0.0.0.0:33531"
    )
    client = _client_for_startup_checks(crash, return_code=1, tmp_path=tmp_path)

    with pytest.raises(RuntimeError) as excinfo:
        client._await_ports(deadline=float("inf"))

    message = str(excinfo.value)
    assert "exited with code 1" in message
    assert "Failed to bind to /0.0.0.0:33531" in message


def test_dead_process_is_reported_while_waiting_for_health(tmp_path):
    """Dying after binding must also fail fast instead of polling a dead port."""
    client = _client_for_startup_checks(
        BANNER + "\nsome fatal error\n", return_code=70, tmp_path=tmp_path
    )

    with pytest.raises(RuntimeError) as excinfo:
        client._wait_for_wiremock(deadline=float("inf"))

    assert "exited with code 70" in str(excinfo.value)
    assert "some fatal error" in str(excinfo.value)


def test_missing_banner_times_out_with_the_captured_output(tmp_path):
    """A live but silent JVM still has to time out -- with its output attached."""
    client = _client_for_startup_checks(
        "still booting\n", return_code=None, tmp_path=tmp_path
    )

    with pytest.raises(TimeoutError) as excinfo:
        client._await_ports(deadline=float("-inf"))

    message = str(excinfo.value)
    assert f"{WIREMOCK_START_TIMEOUT_SECONDS} seconds" in message
    assert "still booting" in message
