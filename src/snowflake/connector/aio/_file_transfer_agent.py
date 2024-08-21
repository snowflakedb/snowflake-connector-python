#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import os
import sys
from logging import getLogger
from typing import IO, TYPE_CHECKING, Any

from ..azure_storage_client import SnowflakeAzureRestClient
from ..constants import (
    AZURE_CHUNK_SIZE,
    AZURE_FS,
    CMD_TYPE_DOWNLOAD,
    CMD_TYPE_UPLOAD,
    GCS_FS,
    LOCAL_FS,
    S3_FS,
    ResultStatus,
    megabyte,
)
from ..errorcode import ER_FILE_NOT_EXISTS
from ..errors import Error, OperationalError
from ..file_transfer_agent import SnowflakeFileMeta
from ..file_transfer_agent import (
    SnowflakeFileTransferAgent as SnowflakeFileTransferAgentSync,
)
from ..file_transfer_agent import (
    SnowflakeProgressPercentage,
    StorageCredential,
    _chunk_size_calculator,
)
from ..gcs_storage_client import SnowflakeGCSRestClient
from ..local_storage_client import SnowflakeLocalStorageClient
from ._s3_storage_client import SnowflakeS3RestClient
from ._storage_client import SnowflakeStorageClient

if TYPE_CHECKING:  # pragma: no cover
    from ._cursor import SnowflakeCursor

VALID_STORAGE = [LOCAL_FS, S3_FS, AZURE_FS, GCS_FS]

INJECT_WAIT_IN_PUT = 0

logger = getLogger(__name__)


class SnowflakeFileTransferAgent(SnowflakeFileTransferAgentSync):
    """Snowflake File Transfer Agent provides cloud provider independent implementation for putting/getting files."""

    def __init__(
        self,
        cursor: SnowflakeCursor,
        command: str,
        ret: dict[str, Any],
        put_callback: type[SnowflakeProgressPercentage] | None = None,
        put_azure_callback: type[SnowflakeProgressPercentage] | None = None,
        put_callback_output_stream: IO[str] = sys.stdout,
        get_callback: type[SnowflakeProgressPercentage] | None = None,
        get_azure_callback: type[SnowflakeProgressPercentage] | None = None,
        get_callback_output_stream: IO[str] = sys.stdout,
        show_progress_bar: bool = True,
        raise_put_get_error: bool = True,
        force_put_overwrite: bool = True,
        skip_upload_on_content_match: bool = False,
        multipart_threshold: int | None = None,
        source_from_stream: IO[bytes] | None = None,
        use_s3_regional_url: bool = False,
    ) -> None:
        self._cursor = cursor
        self._command = command
        self._ret = ret
        self._put_callback = put_callback
        self._put_azure_callback = (
            put_azure_callback if put_azure_callback else put_callback
        )
        self._put_callback_output_stream = put_callback_output_stream
        self._get_callback = get_callback
        self._get_azure_callback = (
            get_azure_callback if get_azure_callback else get_callback
        )
        self._get_callback_output_stream = get_callback_output_stream
        # when we have not checked whether we should use accelerate, this boolean is None
        # _use_accelerate_endpoint in SnowflakeFileTransferAgent could be passed to each SnowflakeS3RestClient
        # so we could avoid check accelerate configuration for each S3 client created for each file meta.
        self._use_accelerate_endpoint: bool | None = None
        self._raise_put_get_error = raise_put_get_error
        self._show_progress_bar = show_progress_bar
        self._force_put_overwrite = force_put_overwrite
        self._skip_upload_on_content_match = skip_upload_on_content_match
        self._source_from_stream = source_from_stream
        # The list of self-sufficient file metas that are sent to
        # remote storage clients to get operated on.
        self._file_metadata: list[SnowflakeFileMeta] = []
        self._results: list[SnowflakeFileMeta] = []
        self._multipart_threshold = multipart_threshold or 67108864  # Historical value
        self._use_s3_regional_url = use_s3_regional_url
        self._credentials: StorageCredential | None = None

    async def execute(self) -> None:
        self._parse_command()
        self._init_file_metadata()

        if self._command_type == CMD_TYPE_UPLOAD:
            self._process_file_compression_type()

        for m in self._file_metadata:
            m.sfagent = self

        self._transfer_accelerate_config()

        if self._command_type == CMD_TYPE_DOWNLOAD:
            if not os.path.isdir(self._local_location):
                os.makedirs(self._local_location)

        if self._stage_location_type == LOCAL_FS:
            if not os.path.isdir(self._stage_info["location"]):
                os.makedirs(self._stage_info["location"])

        for m in self._file_metadata:
            m.overwrite = self._overwrite
            m.skip_upload_on_content_match = self._skip_upload_on_content_match
            m.sfagent = self
            if self._stage_location_type != LOCAL_FS:
                m.put_callback = self._put_callback
                m.put_azure_callback = self._put_azure_callback
                m.put_callback_output_stream = self._put_callback_output_stream
                m.get_callback = self._get_callback
                m.get_azure_callback = self._get_azure_callback
                m.get_callback_output_stream = self._get_callback_output_stream
                m.show_progress_bar = self._show_progress_bar

                # multichunk threshold
                m.multipart_threshold = self._multipart_threshold

        logger.debug(f"parallel=[{self._parallel}]")
        if self._raise_put_get_error and not self._file_metadata:
            Error.errorhandler_wrapper(
                self._cursor.connection,
                self._cursor,
                OperationalError,
                {
                    "msg": "While getting file(s) there was an error: "
                    "the file does not exist.",
                    "errno": ER_FILE_NOT_EXISTS,
                },
            )
        await self.transfer(self._file_metadata)

        # turn enum to string, in order to have backward compatible interface

        for result in self._results:
            result.result_status = result.result_status.value

    async def transfer(self, metas: list[SnowflakeFileMeta]) -> None:
        max_concurrency = self._parallel
        logger.debug(f"Chunk ThreadPoolExecutor size: {max_concurrency}")
        files = [self._create_file_transfer_client(m) for m in metas]
        is_upload = self._command_type == CMD_TYPE_UPLOAD
        finish_upload_tasks = []

        async def preprocess_done_cb(
            success: bool,
            result: Any,
            done_client: SnowflakeStorageClient,
        ) -> None:
            if not success:
                logger.debug(f"Failed to prepare {done_client.meta.name}.")
                if is_upload:
                    await done_client.finish_upload()
                    done_client.delete_client_data()
                else:
                    done_client.finish_download()
            elif done_client.meta.result_status == ResultStatus.SKIPPED:
                # this case applies to upload only
                return
            else:
                logger.debug(f"Finished preparing file {done_client.meta.name}")
                tasks = []
                for _chunk_id in range(done_client.num_of_chunks):
                    task = (
                        asyncio.create_task(done_client.upload_chunk(_chunk_id))
                        if is_upload
                        else asyncio.create_task(done_client.download_chunk(_chunk_id))
                    )
                    task.add_done_callback(
                        lambda t, ta=task, dc=done_client, _chunk_id=_chunk_id: transfer_done_cb(
                            ta, dc, _chunk_id
                        )
                    )
                    tasks.append(task)
                await asyncio.gather(*tasks)
                await asyncio.gather(*finish_upload_tasks)

        def transfer_done_cb(
            task: asyncio.Task,
            done_client: SnowflakeStorageClient,
            chunk_id: int,
        ) -> None:
            # Note: chunk_id is 0 based while num_of_chunks is count
            logger.debug(
                f"Chunk {chunk_id}/{done_client.num_of_chunks} of file {done_client.meta.name} reached callback"
            )
            if task.exception():
                done_client.failed_transfers += 1
                logger.debug(
                    f"Chunk {chunk_id} of file {done_client.meta.name} failed to transfer for unexpected exception {task.exception()}"
                )
            else:
                done_client.successful_transfers += 1
            logger.debug(
                f"Chunk progress: {done_client.meta.name}: completed: {done_client.successful_transfers} failed: {done_client.failed_transfers} total: {done_client.num_of_chunks}"
            )
            if (
                done_client.successful_transfers + done_client.failed_transfers
                == done_client.num_of_chunks
            ):
                if is_upload:
                    finish_upload_task = asyncio.create_task(
                        done_client.finish_upload()
                    )
                    finish_upload_tasks.append(finish_upload_task)
                    done_client.delete_client_data()
                else:
                    try:
                        result = done_client.finish_download()
                        is_successful = True
                    except Exception as e:
                        result = e
                        is_successful = False
                    postprocess_done_cb(
                        is_successful,
                        result,
                        file_meta=done_client.meta,
                        done_client=done_client,
                    )

                    logger.debug(
                        f"submitting {done_client.meta.name} to done_postprocess"
                    )

        def postprocess_done_cb(
            success: bool,
            result: Any,
            file_meta: SnowflakeFileMeta,
            done_client: SnowflakeStorageClient,
        ) -> None:
            logger.debug(f"File {done_client.meta.name} reached postprocess callback")

            if not success:
                done_client.failed_transfers += 1
                logger.debug(
                    f"File {done_client.meta.name} failed to transfer for unexpected exception {result}"
                )
            # Whether there was an exception or not, we're done the file.

        task_of_files = []
        for file_client in files:
            try:
                res = (
                    await file_client.prepare_upload()
                    if is_upload
                    else await file_client.prepare_download()
                )
                is_successful = True
            except Exception as e:
                res = e
                is_successful = False

            task = asyncio.create_task(
                preprocess_done_cb(is_successful, res, done_client=file_client)
            )
            task_of_files.append(task)
        await asyncio.gather(*task_of_files)

        self._results = metas

    def _create_file_transfer_client(
        self, meta: SnowflakeFileMeta
    ) -> SnowflakeStorageClient:
        if self._stage_location_type == LOCAL_FS:
            return SnowflakeLocalStorageClient(
                meta,
                self._stage_info,
                4 * megabyte,
            )
        elif self._stage_location_type == AZURE_FS:
            return SnowflakeAzureRestClient(
                meta,
                self._credentials,
                AZURE_CHUNK_SIZE,
                self._stage_info,
                use_s3_regional_url=self._use_s3_regional_url,
            )
        elif self._stage_location_type == S3_FS:
            return SnowflakeS3RestClient(
                meta=meta,
                credentials=self._credentials,
                stage_info=self._stage_info,
                chunk_size=_chunk_size_calculator(meta.src_file_size),
                use_accelerate_endpoint=self._use_accelerate_endpoint,
                use_s3_regional_url=self._use_s3_regional_url,
            )
        elif self._stage_location_type == GCS_FS:
            return SnowflakeGCSRestClient(
                meta,
                self._credentials,
                self._stage_info,
                self._cursor._connection,
                self._command,
                use_s3_regional_url=self._use_s3_regional_url,
            )
        raise Exception(f"{self._stage_location_type} is an unknown stage type")
