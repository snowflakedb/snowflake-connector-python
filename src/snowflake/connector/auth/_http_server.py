#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

#
# Copyright (c) 2012-2025 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
import select
import socket
import time
from collections.abc import Callable
from types import TracebackType
from typing import Self

from ..compat import IS_WINDOWS
from ..errorcode import ER_NO_HOSTNAME_FOUND
from ..errors import OperationalError

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

    def __init__(
        self,
        hostname: str = "127.0.0.1",
        buf_size: int = 16384,
    ) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.hostname = hostname
        self.buf_size = buf_size
        if os.getenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "False").lower() == "true":
            if IS_WINDOWS:
                logger.warning(
                    "Configuration SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not available in Windows. Ignoring."
                )
            else:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        try:
            self._socket.bind(
                (
                    os.getenv("SF_AUTH_SOCKET_ADDR", hostname),
                    int(os.getenv("SF_AUTH_SOCKET_PORT", 0)),
                )
            )
        except socket.gaierror as ex:
            if ex.args[0] == socket.EAI_NONAME and hostname == "localhost":
                raise OperationalError(
                    msg="localhost is not found. Ensure /etc/hosts has "
                    "localhost entry.",
                    errno=ER_NO_HOSTNAME_FOUND,
                )
            raise

        try:
            self._socket.listen(0)  # no backlog
            self.port = self._socket.getsockname()[1]
        except Exception as ex:
            logger.error(f"Failed to start listening for auth callback: {ex}")
            self.close()
            raise

    def _try_poll(self, timeout: float | None) -> socket.socket | None:
        read_sockets = select.select([self._socket], [], [], timeout)[0]
        if read_sockets and read_sockets[0] is not None:
            return self._socket.accept()[0]

    def _try_receive_block(
        self, recv: Callable[[socket.socket, int], bytes], timeout: float | None
    ) -> (bytes | None, socket.socket | None):
        client_socket = self._try_poll(timeout)
        if client_socket is not None:
            return recv(client_socket, self.buf_size), client_socket
        return None, None

    def receive_block(
        self,
        max_attempts: int = 15,
        timeout: float | None = 30.0,
    ) -> (list[str] | None, socket.socket | None):
        """Receive a message with a maximum attempt count and a timeout in seconds, blocking."""
        if not self._socket:
            raise RuntimeError(
                "Operation is not supported, server was already shut down."
            )
        recv = _wrap_socket_recv()
        attempt_timeout = timeout / max_attempts if timeout else None
        for attempt in range(max_attempts):
            try:
                raw_block, client_socket = self._try_receive_block(
                    recv, attempt_timeout
                )
                if raw_block:
                    return raw_block.decode("utf-8").split("\r\n"), client_socket
                elif client_socket:
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()
            except BlockingIOError:
                logger.debug(
                    f"BlockingIOError raised from socket.recv on attempt {1+attempt}"
                    " to retrieve callback request"
                )
                if attempt < max_attempts - 1:
                    cooldown = min(attempt_timeout, 0.25) if attempt_timeout else 0.25
                    logger.debug(f"Waiting for {cooldown} seconds before trying again")
                    time.sleep(cooldown)
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
