#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
import select
import socket
import time
import urllib.parse
from collections.abc import Callable
from types import TracebackType

from typing_extensions import Self

from ..compat import IS_WINDOWS

logger = logging.getLogger(__name__)


def _use_msg_dont_wait() -> bool:
    if os.getenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "false").lower() != "true":
        return False
    if IS_WINDOWS:
        logger.warning(
            "Configuration SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT is not available in Windows. Ignoring."
        )
        return False
    return True


def _wrap_socket_recv() -> Callable[[socket.socket, int], bytes]:
    dont_wait = _use_msg_dont_wait()
    if dont_wait:
        # WSL containerized environment sometimes causes socket_client.recv to hang indefinetly
        #   To avoid this, passing the socket.MSG_DONTWAIT flag which raises BlockingIOError if
        #   operation would block
        logger.debug(
            "Will call socket.recv with MSG_DONTWAIT flag due to SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT env var"
        )
    socket_recv = (
        (lambda sock, buf_size: socket.socket.recv(sock, buf_size, socket.MSG_DONTWAIT))
        if dont_wait
        else (lambda sock, buf_size: socket.socket.recv(sock, buf_size))
    )

    def socket_recv_checked(sock: socket.socket, buf_size: int) -> bytes:
        raw = socket_recv(sock, buf_size)
        # when running in a containerized environment, socket_client.recv occasionally returns an empty byte array
        #   an immediate successive call to socket_client.recv gets the actual data
        if len(raw) == 0:
            raw = socket_recv(sock, buf_size)
        return raw

    return socket_recv_checked


class AuthHttpServer:
    """Simple HTTP server to receive callbacks through for auth purposes."""

    DEFAULT_MAX_ATTEMPTS = 15
    DEFAULT_TIMEOUT = 30.0

    PORT_BIND_MAX_ATTEMPTS = 10
    PORT_BIND_TIMEOUT = 20.0

    def __init__(
        self,
        uri: str,
        buf_size: int = 16384,
        redirect_uri: str | None = None,
    ) -> None:
        parsed_uri = urllib.parse.urlparse(uri)
        parsed_redirect = urllib.parse.urlparse(redirect_uri) if redirect_uri else None
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buf_size = buf_size
        if os.getenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "False").lower() == "true":
            if IS_WINDOWS:
                logger.warning(
                    "Configuration SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not available in Windows. Ignoring."
                )
            else:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        if parsed_redirect and self._is_local_uri(parsed_redirect):
            server_port = parsed_redirect.port or 0
        else:
            server_port = parsed_uri.port or 0

        for attempt in range(1, self.DEFAULT_MAX_ATTEMPTS + 1):
            try:
                self._socket.bind(
                    (
                        parsed_uri.hostname,
                        server_port,
                    )
                )
                break
            except socket.gaierror as ex:
                logger.error(
                    f"Failed to bind authorization callback server to port {server_port}: {ex}"
                )
                raise
            except OSError as ex:
                if attempt == self.DEFAULT_MAX_ATTEMPTS:
                    logger.error(
                        f"Failed to bind authorization callback server to port {server_port}: {ex}"
                    )
                    raise
                logger.warning(
                    f"Attempt {attempt}/{self.DEFAULT_MAX_ATTEMPTS}. "
                    f"Failed to bind authorization callback server to port {server_port}: {ex}"
                )
                time.sleep(self.PORT_BIND_TIMEOUT / self.PORT_BIND_MAX_ATTEMPTS)
        try:
            self._socket.listen(0)  # no backlog
        except Exception as ex:
            logger.error(f"Failed to start listening for auth callback: {ex}")
            self.close()
            raise

        server_port = self._socket.getsockname()[1]
        self._uri = urllib.parse.ParseResult(
            scheme=parsed_uri.scheme,
            netloc=parsed_uri.hostname + ":" + str(server_port),
            path=parsed_uri.path,
            params=parsed_uri.params,
            query=parsed_uri.query,
            fragment=parsed_uri.fragment,
        )

        if parsed_redirect:
            if (
                self._is_local_uri(parsed_redirect)
                and server_port != parsed_redirect.port
            ):
                logger.debug(
                    f"Updating redirect port {parsed_redirect.port} to match the server port {server_port}."
                )
                self._redirect_uri = urllib.parse.ParseResult(
                    scheme=parsed_redirect.scheme,
                    netloc=parsed_redirect.hostname + ":" + str(server_port),
                    path=parsed_redirect.path,
                    params=parsed_redirect.params,
                    query=parsed_redirect.query,
                    fragment=parsed_redirect.fragment,
                )
            else:
                self._redirect_uri = parsed_redirect
        else:
            # For backwards compatibility
            self._redirect_uri = self._uri

    @staticmethod
    def _is_local_uri(uri):
        return uri.hostname in ("localhost", "127.0.0.1")

    @property
    def redirect_uri(self) -> str | None:
        return self._redirect_uri.geturl()

    @property
    def url(self) -> str:
        return self._uri.geturl()

    @property
    def port(self) -> int:
        return self._uri.port

    @property
    def hostname(self) -> str:
        return self._uri.hostname

    def _seconds_until(self, deadline: float) -> float:
        return max(0.0, deadline - time.monotonic())

    def _poll_for_client(
        self,
        deadline: float,
        slice_timeout: float | None,
        max_attempts: int,
    ) -> socket.socket | None:
        """Wait until a client connects, ``deadline``, or ``max_attempts`` poll iterations."""
        for _ in range(max_attempts):
            if self._seconds_until(deadline) <= 0:
                break
            remaining = self._seconds_until(deadline)
            if slice_timeout is not None:
                sel_timeout = min(remaining, slice_timeout)
            else:
                sel_timeout = remaining
            # Avoid zero-timeout busy loops when slice rounds down
            if sel_timeout <= 0:
                break
            read_sockets = select.select([self._socket], [], [], sel_timeout)[0]
            if read_sockets and read_sockets[0] is not None:
                return self._socket.accept()[0]
        return None

    def _receive_first_chunk_until(
        self,
        client_socket: socket.socket,
        deadline: float,
        slice_timeout: float | None,
        max_attempts: int,
    ) -> bytes | None:
        """Read the first chunk before ``deadline`` or ``max_attempts`` blocking recv timeouts.

        ``max_attempts`` counts socket timeouts only, not ``BlockingIOError`` retries
        (MSG_DONTWAIT path), so WSL-style polling does not exhaust the recv budget early.
        """
        recv = _wrap_socket_recv()
        use_dont_wait = _use_msg_dont_wait()
        recv_timeouts = 0
        while self._seconds_until(deadline) > 0 and recv_timeouts < max_attempts:
            remaining = self._seconds_until(deadline)
            per_op_timeout = (
                min(remaining, slice_timeout) if slice_timeout is not None else remaining
            )
            if not use_dont_wait and per_op_timeout > 0:
                client_socket.settimeout(per_op_timeout)
            try:
                return recv(client_socket, self.buf_size)
            except BlockingIOError:
                cooldown = min(0.25, per_op_timeout, remaining) if per_op_timeout else min(
                    0.25, remaining
                )
                if cooldown <= 0:
                    cooldown = min(0.001, remaining) if remaining > 0 else 0
                if cooldown > 0:
                    logger.debug(
                        "BlockingIOError from socket.recv while waiting for auth callback; "
                        f"sleeping {cooldown} s before retry"
                    )
                    time.sleep(cooldown)
            except socket.timeout:
                recv_timeouts += 1
                logger.debug("socket.recv timed out while waiting for auth callback; retrying")
        return None

    def receive_block(
        self,
        max_attempts: int = None,
        timeout: float | int | None = None,
    ) -> tuple[list[str] | None, socket.socket | None]:
        """Receive a message within ``timeout`` seconds (wall clock), blocking.

        ``max_attempts`` caps poll iterations and blocking recv timeouts (full budget for
        recv, not reduced by poll usage). It also sets per-iteration select/recv slice
        size as ``timeout / max_attempts`` when both are positive.
        """
        if max_attempts is None:
            max_attempts = self.DEFAULT_MAX_ATTEMPTS
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        timeout_f = float(timeout)
        if not self._socket:
            raise RuntimeError(
                "Operation is not supported, server was already shut down."
            )
        ma = max(1, max_attempts)
        deadline = time.monotonic() + timeout_f
        slice_timeout = (timeout_f / ma) if timeout_f > 0 else None

        client_socket = self._poll_for_client(deadline, slice_timeout, ma)
        if client_socket is None:
            return None, None

        raw_block = self._receive_first_chunk_until(
            client_socket, deadline, slice_timeout, ma
        )
        if raw_block:
            return raw_block.decode("utf-8").split("\r\n"), client_socket
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client_socket.close()
        return None, None

    def close(self) -> None:
        """Closes the underlying socket.
        After having close() being called the server object cannot be reused.
        """
        if self._socket:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> Self:
        """Context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager with disposing underlying networking objects."""
        self.close()
