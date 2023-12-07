#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .file_transfer_agent import *
from .file_transfer_agent import _chunk_size_calculator
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

    def _create_file_transfer_client(
        self, meta: SnowflakeFileMeta
    ) -> SnowflakeStorageClient:
        if self._stage_location_type == LOCAL_FS:
            raise Exception("Local not supported for SnowflakeFileTransferAgentAsync")
        elif self._stage_location_type == AZURE_FS:
            raise Exception("Azure not supported for SnowflakeFileTransferAgentAsync")
        elif self._stage_location_type == S3_FS:
            from .s3_storage_client_async import SnowflakeS3RestClientAsync

            return SnowflakeS3RestClientAsync(
                meta,
                self._credentials,
                self._stage_info,
                _chunk_size_calculator(meta.src_file_size),
                use_accelerate_endpoint=self._use_accelerate_endpoint,
                use_s3_regional_url=self._use_s3_regional_url,
            )
        elif self._stage_location_type == GCS_FS:
            raise Exception("GCS not supported for SnowflakeFileTransferAgentAsync")
        raise Exception(f"{self._stage_location_type} is an unknown stage type")

    def close(self) -> None:
        self._loop_runner.stop()
