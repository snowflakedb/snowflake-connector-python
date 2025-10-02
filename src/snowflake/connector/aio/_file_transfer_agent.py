from __future__ import annotations

import asyncio
import os
import sys
from logging import getLogger
from typing import IO, TYPE_CHECKING, Any

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
from ..file_transfer_agent import SnowflakeProgressPercentage, _chunk_size_calculator
from ..local_storage_client import SnowflakeLocalStorageClient
from ._azure_storage_client import SnowflakeAzureRestClient
from ._gcs_storage_client import SnowflakeGCSRestClient
from ._s3_storage_client import SnowflakeS3RestClient
from ._storage_client import SnowflakeStorageClient

if TYPE_CHECKING:  # pragma: no cover
    from ._cursor import SnowflakeCursor


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
        unsafe_file_write: bool = False,
        reraise_error_in_file_transfer_work_function: bool = False,
    ) -> None:
        super().__init__(
            cursor=cursor,
            command=command,
            ret=ret,
            put_callback=put_callback,
            put_azure_callback=put_azure_callback,
            put_callback_output_stream=put_callback_output_stream,
            get_callback=get_callback,
            get_azure_callback=get_azure_callback,
            get_callback_output_stream=get_callback_output_stream,
            show_progress_bar=show_progress_bar,
            raise_put_get_error=raise_put_get_error,
            force_put_overwrite=force_put_overwrite,
            skip_upload_on_content_match=skip_upload_on_content_match,
            multipart_threshold=multipart_threshold,
            source_from_stream=source_from_stream,
            use_s3_regional_url=use_s3_regional_url,
            unsafe_file_write=unsafe_file_write,
            reraise_error_in_file_transfer_work_function=reraise_error_in_file_transfer_work_function,
        )

    async def execute(self) -> None:
        self._parse_command()
        self._init_file_metadata()

        if self._command_type == CMD_TYPE_UPLOAD:
            self._process_file_compression_type()

        for m in self._file_metadata:
            m.sfagent = self

        await self._transfer_accelerate_config()

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

        # TODO: SNOW-1625364 for renaming client_prefetch_threads in asyncio
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
        files = [await self._create_file_transfer_client(m) for m in metas]
        is_upload = self._command_type == CMD_TYPE_UPLOAD
        finish_download_upload_tasks = []

        async def preprocess_done_cb(
            success: bool,
            result: Any,
            done_client: SnowflakeStorageClient,
        ) -> None:
            if not success:
                logger.debug(f"Failed to prepare {done_client.meta.name}.")
                try:
                    if is_upload:
                        await done_client.finish_upload()
                        done_client.delete_client_data()
                    else:
                        await done_client.finish_download()
                except Exception as error:
                    done_client.meta.error_details = error
            elif done_client.meta.result_status == ResultStatus.SKIPPED:
                # this case applies to upload only
                return
            else:
                try:
                    logger.debug(f"Finished preparing file {done_client.meta.name}")
                    tasks = []
                    for _chunk_id in range(done_client.num_of_chunks):
                        task = (
                            asyncio.create_task(done_client.upload_chunk(_chunk_id))
                            if is_upload
                            else asyncio.create_task(
                                done_client.download_chunk(_chunk_id)
                            )
                        )
                        task.add_done_callback(
                            lambda t, dc=done_client, _chunk_id=_chunk_id: transfer_done_cb(
                                t, dc, _chunk_id
                            )
                        )
                        tasks.append(task)
                    await asyncio.gather(*tasks)
                    await asyncio.gather(*finish_download_upload_tasks)
                except Exception as error:
                    done_client.meta.error_details = error
                    if self._reraise_error_in_file_transfer_work_function:
                        # Propagate task exceptions to the caller to fail the transfer early.
                        raise

        def transfer_done_cb(
            task: asyncio.Task,
            done_client: SnowflakeStorageClient,
            chunk_id: int,
        ) -> None:
            # Note: chunk_id is 0 based while num_of_chunks is count
            logger.debug(
                f"Chunk(id: {chunk_id}) {chunk_id+1}/{done_client.num_of_chunks} of file {done_client.meta.name} reached callback"
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
                    finish_download_upload_tasks.append(finish_upload_task)
                    done_client.delete_client_data()
                else:
                    finish_download_task = asyncio.create_task(
                        done_client.finish_download()
                    )
                    finish_download_task.add_done_callback(
                        lambda t, dc=done_client: postprocess_done_cb(t, dc)
                    )
                    finish_download_upload_tasks.append(finish_download_task)

        def postprocess_done_cb(
            task: asyncio.Task,
            done_client: SnowflakeStorageClient,
        ) -> None:
            logger.debug(f"File {done_client.meta.name} reached postprocess callback")

            if task.exception():
                done_client.failed_transfers += 1
                logger.debug(
                    f"File {done_client.meta.name} failed to transfer for unexpected exception {task.exception()}"
                )
            # Whether there was an exception or not, we're done the file.

        task_of_files = []
        for file_client in files:
            try:
                # TODO: SNOW-1708819 for code refactoring
                res = (
                    await file_client.prepare_upload()
                    if is_upload
                    else await file_client.prepare_download()
                )
                is_successful = True
            except Exception as e:
                res = e
                file_client.meta.error_details = e
                is_successful = False

            task = asyncio.create_task(
                preprocess_done_cb(is_successful, res, done_client=file_client)
            )
            task_of_files.append(task)
        await asyncio.gather(*task_of_files)

        self._results = metas

    async def _transfer_accelerate_config(self) -> None:
        if self._stage_location_type == S3_FS and self._file_metadata:
            client = await self._create_file_transfer_client(self._file_metadata[0])
            self._use_accelerate_endpoint = await client.transfer_accelerate_config()

    async def _create_file_transfer_client(
        self, meta: SnowflakeFileMeta
    ) -> SnowflakeStorageClient:
        if self._stage_location_type == LOCAL_FS:
            return SnowflakeLocalStorageClient(
                meta,
                self._stage_info,
                4 * megabyte,
                unsafe_file_write=self._unsafe_file_write,
            )
        elif self._stage_location_type == AZURE_FS:
            return SnowflakeAzureRestClient(
                meta,
                self._credentials,
                AZURE_CHUNK_SIZE,
                self._stage_info,
                unsafe_file_write=self._unsafe_file_write,
            )
        elif self._stage_location_type == S3_FS:
            client = SnowflakeS3RestClient(
                meta=meta,
                credentials=self._credentials,
                stage_info=self._stage_info,
                chunk_size=_chunk_size_calculator(meta.src_file_size),
                use_accelerate_endpoint=self._use_accelerate_endpoint,
                use_s3_regional_url=self._use_s3_regional_url,
                unsafe_file_write=self._unsafe_file_write,
            )
            await client.transfer_accelerate_config(self._use_accelerate_endpoint)
            return client
        elif self._stage_location_type == GCS_FS:
            client = SnowflakeGCSRestClient(
                meta,
                self._credentials,
                self._stage_info,
                self._cursor._connection,
                self._command,
                unsafe_file_write=self._unsafe_file_write,
            )
            if client.security_token:
                logger.debug(f"len(GCS_ACCESS_TOKEN): {len(client.security_token)}")
            else:
                logger.debug(
                    "No access token received from GS, requesting presigned url"
                )
                await client._update_presigned_url()
            return client
        raise Exception(f"{self._stage_location_type} is an unknown stage type")
