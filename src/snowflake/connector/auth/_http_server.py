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
    ) -> None:
        parsed_uri = urllib.parse.urlparse(uri)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buf_size = buf_size
        if os.getenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "False").lower() == "true":
            if IS_WINDOWS:
                logger.warning(
                    "Configuration SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not available in Windows. Ignoring."
                )
            else:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        port = parsed_uri.port or 0
        for attempt in range(1, self.DEFAULT_MAX_ATTEMPTS + 1):
            try:
                self._socket.bind(
                    (
                        parsed_uri.hostname,
                        port,
                    )
                )
                break
            except socket.gaierror as ex:
                logger.error(
                    f"Failed to bind authorization callback server to port {port}: {ex}"
                )
                raise
            except OSError as ex:
                if attempt == self.DEFAULT_MAX_ATTEMPTS:
                    logger.error(
                        f"Failed to bind authorization callback server to port {port}: {ex}"
                    )
                    raise
                logger.warning(
                    f"Attempt {attempt}/{self.DEFAULT_MAX_ATTEMPTS}. "
                    f"Failed to bind authorization callback server to port {port}: {ex}"
                )
                time.sleep(self.PORT_BIND_TIMEOUT / self.PORT_BIND_MAX_ATTEMPTS)
        try:
            self._socket.listen(0)  # no backlog
        except Exception as ex:
            logger.error(f"Failed to start listening for auth callback: {ex}")
            self.close()
            raise
        port = self._socket.getsockname()[1]
        self._uri = urllib.parse.ParseResult(
            scheme=parsed_uri.scheme,
            netloc=parsed_uri.hostname + ":" + str(port),
            path=parsed_uri.path,
            params=parsed_uri.params,
            query=parsed_uri.query,
            fragment=parsed_uri.fragment,
        )

    @property
    def url(self) -> str:
        return self._uri.geturl()

    @property
    def port(self) -> int:
        return self._uri.port

    @property
    def hostname(self) -> str:
        return self._uri.hostname

    def _try_poll(
        self, attempts: int, attempt_timeout: float | None
    ) -> (socket.socket | None, int):
        for attempt in range(attempts):
            read_sockets = select.select([self._socket], [], [], attempt_timeout)[0]
            if read_sockets and read_sockets[0] is not None:
                return self._socket.accept()[0], attempt
        return None, attempts

    def _try_receive_block(
        self, client_socket: socket.socket, attempts: int, attempt_timeout: float | None
    ) -> bytes | None:
        if attempt_timeout is not None:
            client_socket.settimeout(attempt_timeout)
        recv = _wrap_socket_recv()
        for attempt in range(attempts):
            try:
                return recv(client_socket, self.buf_size)
            except BlockingIOError:
                if attempt < attempts - 1:
                    cooldown = min(attempt_timeout, 0.25) if attempt_timeout else 0.25
                    logger.debug(
                        f"BlockingIOError raised from socket.recv on {1 + attempt}/{attempts} attempt."
                        f"Waiting for {cooldown} seconds before trying again"
                    )
                    time.sleep(cooldown)
            except socket.timeout:
                logger.debug(
                    f"socket.recv timed out on {1 + attempt}/{attempts} attempt."
                )
        return None

    def receive_block(
        self,
        max_attempts: int = None,
        timeout: float | int | None = None,
    ) -> (list[str] | None, socket.socket | None):
        if max_attempts is None:
            max_attempts = self.DEFAULT_MAX_ATTEMPTS
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        """Receive a message with a maximum attempt count and a timeout in seconds, blocking."""
        if not self._socket:
            raise RuntimeError(
                "Operation is not supported, server was already shut down."
            )
        attempt_timeout = timeout / max_attempts if timeout else None
        client_socket, poll_attempts = self._try_poll(max_attempts, attempt_timeout)
        if client_socket is None:
            return None, None
        raw_block = self._try_receive_block(
            client_socket, max_attempts - poll_attempts, attempt_timeout
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
