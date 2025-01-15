#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
import select
import socket
import time

from ..compat import IS_WINDOWS
from ..errorcode import ER_NO_HOSTNAME_FOUND
from ..errors import OperationalError

logger = logging.getLogger(__name__)


class AuthHttpServer:
    """Simple HTTP server to receive callbacks through for auth purposes."""

    def __init__(
        self,
        hostname: str = "localhost",
        buf_size: int = 16384,
    ) -> None:
        self.buf_size = buf_size
        self._socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if os.getenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "False").lower() == "true":
            if IS_WINDOWS:
                logger.warning(
                    "Configuration SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not available in Windows. Ignoring."
                )
            else:
                self._socket_connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEPORT, 1
                )

        try:
            self._socket_connection.bind(
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
            self._socket_connection.listen(0)  # no backlog
            self.port = self._socket_connection.getsockname()[1]
        except Exception:
            self._socket_connection.close()

    def receive_block(
        self,
        max_attempts: int = 15,
    ) -> tuple[list[str], socket.socket]:
        """Receive a message with a maximum attempt count, blocking."""
        socket_client = None
        while True:
            try:
                attempts = 0
                raw_data = bytearray()

                msg_dont_wait = (
                    os.getenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "false").lower()
                    == "true"
                )
                if IS_WINDOWS:
                    if msg_dont_wait:
                        logger.warning(
                            "Configuration SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT is not available in Windows. Ignoring."
                        )
                    msg_dont_wait = False

                # when running in a containerized environment, socket_client.recv ocassionally returns an empty byte array
                #   an immediate successive call to socket_client.recv gets the actual data
                while len(raw_data) == 0 and attempts < max_attempts:
                    attempts += 1
                    read_sockets, _write_sockets, _exception_sockets = select.select(
                        [self._socket_connection], [], []
                    )

                    if read_sockets[0] is not None:
                        # Receive the data in small chunks and retransmit it
                        socket_client, _ = self._socket_connection.accept()

                        try:
                            if msg_dont_wait:
                                # WSL containerized environment sometimes causes socket_client.recv to hang indefinetly
                                #   To avoid this, passing the socket.MSG_DONTWAIT flag which raises BlockingIOError if
                                #   operation would block
                                logger.debug(
                                    "Calling socket_client.recv with MSG_DONTWAIT flag due to SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT env var"
                                )
                                raw_data = socket_client.recv(
                                    BUF_SIZE, socket.MSG_DONTWAIT
                                )
                            else:
                                raw_data = socket_client.recv(self.buf_size)

                        except BlockingIOError:
                            logger.debug(
                                "BlockingIOError raised from socket.recv while attempting to retrieve callback request"
                            )
                            if attempts < max_attempts:
                                sleep_time = 0.25
                                logger.debug(
                                    f"Waiting {sleep_time} seconds before trying again"
                                )
                                time.sleep(sleep_time)
                            else:
                                logger.debug("Exceeded retry count")

                assert socket_client is not None
                return raw_data.decode("utf-8").split("\r\n"), socket_client
            except Exception:
                if socket_client is not None:
                    socket_client.shutdown(socket.SHUT_RDWR)
                    socket_client.close()
