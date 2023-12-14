#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .constants import AZURE_FS, GCS_FS, LOCAL_FS, S3_FS
from .file_transfer_agent import (
    SnowflakeFileMeta,
    SnowflakeFileTransferAgent,
    _chunk_size_calculator,
)
from .storage_client import SnowflakeStorageClient

# YICHUAN: SnowflakeFileTransferAgentAsync is identical to SnowflakeFileTransferAgent, except it uses instances of
# SnowflakeStorageClientAsync instead of SnowflakeStorageClient


class SnowflakeFileTransferAgentAsync(SnowflakeFileTransferAgent):
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
