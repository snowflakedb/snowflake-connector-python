#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .file_transfer_agent import *
from .network_async import EventLoopThreadRunner

# YICHUAN: SnowflakeFileTransferAgentAsync is identical to SnowflakeFileTransferAgent, except for two differences; it
# owns an EventLoopThreadRunner and uses instances of SnowflakeStorageClientAsync


class SnowflakeFileTransferAgentAsync(SnowflakeFileTransferAgent):
    def __init__(self, *args, **kwargs) -> None:
        # YICHUAN: This EventLoopThreadRunner may never be used if there is one available in the SnowflakeRestfulAsync
        # instance owned by SnowflakeConnector, but a thread running an event loop that does nothing is lightweight
        # and saves us headaches if no SnowflakeConnector instance is associated to a transfer
        self._loop_runner = EventLoopThreadRunner()
        self._loop_runner.start()

        super().__init__(*args, **kwargs)

    def close(self) -> None:
        self._loop_runner.stop()
