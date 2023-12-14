#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import os
import shutil
import ssl
from abc import abstractmethod
from logging import getLogger
from math import ceil
from typing import Any, Callable

import aiohttp

from .constants import FileHeader, ResultStatus
from .encryption_util import SnowflakeEncryptionUtil
from .errors import RequestExceedMaxRetryError
from .event_loop_runner import LOOP_RUNNER
from .network_async import get_default_aiohttp_session_request_kwargs, make_client_session
from .storage_client import SnowflakeStorageClient

logger = getLogger(__name__)

# YICHUAN: Not much to explain in this file, we add async versions of existing private methods and override public
# methods to call async private methods instead
# We explicitly add new private methods with suffix "_async" for clarity instead of overriding


class SnowflakeStorageClientAsync(SnowflakeStorageClient):
    TRANSIENT_ERRORS_ASYNC = (
        ssl.SSLSyscallError,
        asyncio.TimeoutError,
        aiohttp.ClientConnectionError,
    )

    @abstractmethod
    async def get_file_header_async(self, filename: str) -> FileHeader | None:
        pass

    def preprocess(self) -> None:
        meta = self.meta
        logger.debug(f"Preprocessing {meta.src_file_name}")

        # check if file exists on remote
        file_header = LOOP_RUNNER.run_coro(
            self.get_file_header_async(meta.dst_file_name)
        )
        if not meta.overwrite:
            self.get_digest()  # self.get_file_header needs digest for multiparts upload when aws is used.
            if meta.result_status == ResultStatus.UPLOADED:
                # Skipped
                logger.debug(
                    f'file already exists location="{self.stage_info["location"]}", '
                    f'file_name="{meta.dst_file_name}"'
                )
                meta.dst_file_size = 0
                meta.result_status = ResultStatus.SKIPPED
                self.preprocessed = True
                return
        # Uploading
        if meta.require_compress:
            self.compress()
        self.get_digest()

        if (
            meta.skip_upload_on_content_match
            and file_header
            and meta.sha256_digest == file_header.digest
        ):
            logger.debug(f"same file contents for {meta.name}, skipping upload")
            meta.result_status = ResultStatus.SKIPPED

        self.preprocessed = True

    def prepare_upload(self) -> None:
        meta = self.meta

        if not self.preprocessed:
            self.preprocess()
        elif meta.encryption_material:
            # need to clean up previous encrypted file
            os.remove(self.data_file)

        logger.debug(f"Preparing to upload {meta.src_file_name}")

        if meta.encryption_material:
            self.encrypt()
        else:
            self.data_file = meta.real_src_file_name
        logger.debug("finished preprocessing")
        meta.multipart_threshold = 0
        if meta.upload_size < meta.multipart_threshold or not self.chunked_transfer:
            self.num_of_chunks = 1
        else:
            self.num_of_chunks = ceil(meta.upload_size / self.chunk_size)
        logger.debug(f"number of chunks {self.num_of_chunks}")
        # clean up
        self.retry_count = {}

        for chunk_id in range(self.num_of_chunks):
            self.retry_count[chunk_id] = 0
        if self.chunked_transfer and self.num_of_chunks > 1:
            LOOP_RUNNER.run_coro(self._initiate_multipart_upload_async())

    @abstractmethod
    async def _has_expired_token_async(self, response: aiohttp.ClientResponse) -> bool:
        pass

    async def _send_request_with_retry_async(
        self,
        verb: str,
        get_request_args: Callable[[], tuple[bytes, dict[str, Any]]],
        retry_id: int,
    ) -> aiohttp.ClientResponse:
        url = ""  # YICHUAN: Not sure why this is a bytes string in original version, but aiohttp doesn't like bytes
        if self.meta.sfagent and self.meta.sfagent._cursor.connection:
            conn = self.meta.sfagent._cursor.connection

        while self.retry_count[retry_id] < self.max_retry:
            cur_timestamp = self.credentials.timestamp
            url, rest_kwargs = get_request_args()
            try:
                logger.debug("storage client request with session from connection")
                if conn:
                    session_manager = conn._rest._use_requests_session_async(url)
                else:
                    session_manager = make_client_session(LOOP_RUNNER.loop)

                # YICHUAN: Self explanatory, of course get_request_args needs to be modified for aiohttp as well
                async with session_manager as session:
                    response = await session.request(
                        method=verb,
                        url=url,
                        **(
                            rest_kwargs
                            | get_default_aiohttp_session_request_kwargs(url=url)
                        ),
                    )

                if await self._has_expired_presigned_url_async(response):
                    self._update_presigned_url()
                else:
                    self.last_err_is_presigned_url = False
                    if response.status in self.TRANSIENT_HTTP_ERR:
                        await asyncio.sleep(
                            min(
                                # TODO should SLEEP_UNIT come from the parent
                                #  SnowflakeConnection and be customizable by users?
                                (2 ** self.retry_count[retry_id]) * self.SLEEP_UNIT,
                                self.SLEEP_MAX,
                            )
                        )
                        self.retry_count[retry_id] += 1
                    elif await self._has_expired_token_async(response):
                        self.credentials.update(cur_timestamp)
                    else:
                        return response
            except self.TRANSIENT_ERRORS_ASYNC as e:
                self.last_err_is_presigned_url = False
                await asyncio.sleep(
                    min(
                        (2 ** self.retry_count[retry_id]) * self.SLEEP_UNIT,
                        self.SLEEP_MAX,
                    )
                )
                logger.warning(f"{verb} with url {url} failed for transient error: {e}")
                self.retry_count[retry_id] += 1
        else:
            raise RequestExceedMaxRetryError(
                f"{verb} with url {url} failed for exceeding maximum retries."
            )

    def prepare_download(self) -> None:
        # TODO: add nicer error message for when target directory is not writeable
        #  but this should be done before we get here
        base_dir = os.path.dirname(self.full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        # HEAD
        file_header = LOOP_RUNNER.run_coro(
            self.get_file_header_async(self.meta.real_src_file_name)
        )

        if file_header and file_header.encryption_metadata:
            self.encryption_metadata = file_header.encryption_metadata

        self.num_of_chunks = 1
        if file_header and file_header.content_length:
            self.meta.src_file_size = file_header.content_length
            if (
                self.chunked_transfer
                and self.meta.src_file_size > self.meta.multipart_threshold
            ):
                self.num_of_chunks = ceil(file_header.content_length / self.chunk_size)

        # Preallocate encrypted file.
        with self.intermediate_dst_path.open("wb+") as fd:
            fd.truncate(self.meta.src_file_size)

    def finish_upload(self) -> None:
        meta = self.meta
        if self.successful_transfers == self.num_of_chunks:
            if self.num_of_chunks > 1:
                LOOP_RUNNER.run_coro(self._complete_multipart_upload_async())
            meta.result_status = ResultStatus.UPLOADED
            meta.dst_file_size = meta.upload_size
            logger.debug(f"{meta.src_file_name} upload is completed.")
        else:
            # TODO: add more error details to result/meta
            meta.dst_file_size = 0
            logger.debug(f"{meta.src_file_name} upload is aborted.")
            if self.num_of_chunks > 1:
                LOOP_RUNNER.run_coro(self._abort_multipart_upload_async())
            meta.result_status = ResultStatus.ERROR

    def finish_download(self) -> None:
        meta = self.meta
        if self.num_of_chunks != 0 and self.successful_transfers == self.num_of_chunks:
            meta.result_status = ResultStatus.DOWNLOADED
            if meta.encryption_material:
                logger.debug(f"encrypted data file={self.full_dst_file_name}")
                # For storage utils that do not have the privilege of
                # getting the metadata early, both object and metadata
                # are downloaded at once. In which case, the file meta will
                # be updated with all the metadata that we need and
                # then we can call get_file_header to get just that and also
                # preserve the idea of getting metadata in the first place.
                # One example of this is the utils that use presigned url
                # for upload/download and not the storage client library.
                if meta.presigned_url is not None:
                    file_header = LOOP_RUNNER.run_coro(
                        self.get_file_header_async(meta.src_file_name)
                    )
                    self.encryption_metadata = file_header.encryption_metadata

                tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                    self.encryption_metadata,
                    meta.encryption_material,
                    str(self.intermediate_dst_path),
                    tmp_dir=self.tmp_dir,
                )
                shutil.move(tmp_dst_file_name, self.full_dst_file_name)
                self.intermediate_dst_path.unlink()
            else:
                logger.debug(f"not encrypted data file={self.full_dst_file_name}")
                shutil.move(str(self.intermediate_dst_path), self.full_dst_file_name)
            stat_info = os.stat(self.full_dst_file_name)
            meta.dst_file_size = stat_info.st_size
        else:
            # TODO: add more error details to result/meta
            if os.path.isfile(self.full_dst_file_name):
                os.unlink(self.full_dst_file_name)
            logger.exception(f"Failed to download a file: {self.full_dst_file_name}")
            meta.dst_file_size = -1
            meta.result_status = ResultStatus.ERROR

    def upload_chunk(self, chunk_id: int) -> None:
        new_stream = not bool(self.meta.src_stream or self.meta.intermediate_stream)
        fd = (
            self.meta.src_stream
            or self.meta.intermediate_stream
            or open(self.data_file, "rb")
        )
        try:
            if self.num_of_chunks == 1:
                _data = fd.read()
            else:
                fd.seek(chunk_id * self.chunk_size)
                _data = fd.read(self.chunk_size)
        finally:
            if new_stream:
                fd.close()
        logger.debug(f"Uploading chunk {chunk_id} of file {self.data_file}")
        LOOP_RUNNER.run_coro(self._upload_chunk_async(chunk_id, _data))
        logger.debug(f"Successfully uploaded chunk {chunk_id} of file {self.data_file}")

    @abstractmethod
    async def _upload_chunk_async(self, chunk_id: int, chunk: bytes) -> None:
        pass

    def download_chunk(self, chunk_id: int) -> None:
        LOOP_RUNNER.run_coro(self._download_chunk_async(chunk_id))

    @abstractmethod
    async def _download_chunk_async(self, chunk_id: int) -> None:
        pass

    # Override in GCS
    async def _has_expired_presigned_url_async(
        self, response: aiohttp.ClientResponse
    ) -> bool:
        return False

    # Override in S3
    async def _initiate_multipart_upload_async(self) -> None:
        return

    # Override in S3
    async def _complete_multipart_upload_async(self) -> None:
        return

    # Override in S3
    async def _abort_multipart_upload_async(self) -> None:
        return
