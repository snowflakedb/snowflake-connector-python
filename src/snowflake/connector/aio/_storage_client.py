#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
import time
from abc import abstractmethod
from logging import getLogger
from typing import TYPE_CHECKING, Any, Callable

import aiohttp

from ..constants import FileHeader, ResultStatus
from ..errors import RequestExceedMaxRetryError
from ..storage_client import SnowflakeStorageClient as SnowflakeStorageClientSync
from ..vendored import requests

if TYPE_CHECKING:  # pragma: no cover
    from ..file_transfer_agent import SnowflakeFileMeta, StorageCredential

logger = getLogger(__name__)

METHODS = {
    "GET": requests.get,
    "PUT": requests.put,
    "POST": requests.post,
    "HEAD": requests.head,
    "DELETE": requests.delete,
}


class SnowflakeStorageClient(SnowflakeStorageClientSync):
    def __init__(
        self,
        meta: SnowflakeFileMeta,
        stage_info: dict[str, Any],
        chunk_size: int,
        chunked_transfer: bool | None = True,
        credentials: StorageCredential | None = None,
        max_retry: int = 5,
    ) -> None:
        SnowflakeStorageClientSync.__init__(
            self,
            meta=meta,
            stage_info=stage_info,
            chunk_size=chunk_size,
            chunked_transfer=chunked_transfer,
            credentials=credentials,
            max_retry=max_retry,
        )

    @abstractmethod
    async def get_file_header(self, filename: str) -> FileHeader | None:
        """Check if file exists in target location and obtain file metadata if exists.

        Notes:
            Updates meta.result_status.
        """
        pass

    async def preprocess(self) -> None:
        meta = self.meta
        logger.debug(f"Preprocessing {meta.src_file_name}")
        file_header = await self.get_file_header(
            meta.dst_file_name
        )  # check if file exists on remote
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

    async def prepare_upload(self) -> None:
        meta = self.meta

        if not self.preprocessed:
            await self.preprocess()
        elif meta.encryption_material:
            # need to clean up previous encrypted file
            os.remove(self.data_file)
        logger.debug(f"Preparing to upload {meta.src_file_name}")

        if meta.encryption_material:
            self.encrypt()
        else:
            self.data_file = meta.real_src_file_name
        logger.debug("finished preprocessing")
        if meta.upload_size < meta.multipart_threshold or not self.chunked_transfer:
            self.num_of_chunks = 1
        else:
            # self.num_of_chunks = ceil(meta.upload_size / self.chunk_size)
            # only needed in big file transfer
            pass
        logger.debug(f"number of chunks {self.num_of_chunks}")
        # clean up
        self.retry_count = {}

        for chunk_id in range(self.num_of_chunks):
            self.retry_count[chunk_id] = 0
        # only used in big file transfer
        # if self.chunked_transfer and self.num_of_chunks > 1:
        #     await self._initiate_multipart_upload()

    async def finish_upload(self) -> None:
        meta = self.meta
        if self.successful_transfers == self.num_of_chunks and self.num_of_chunks != 0:
            # only needed in big file transfer
            # if self.num_of_chunks > 1:
            #     await self._complete_multipart_upload()
            meta.result_status = ResultStatus.UPLOADED
            meta.dst_file_size = meta.upload_size
            logger.debug(f"{meta.src_file_name} upload is completed.")
        else:
            # TODO: add more error details to result/meta
            meta.dst_file_size = 0
            logger.debug(f"{meta.src_file_name} upload is aborted.")
            # only needed in big file transfer
            # if self.num_of_chunks > 1:
            #     await self._abort_multipart_upload()
            meta.result_status = ResultStatus.ERROR

    async def _send_request_with_retry(
        self,
        verb: str,
        get_request_args: Callable[[], tuple[str, dict[str, bytes]]],
        retry_id: int,
    ) -> aiohttp.ClientResponse:
        url = ""
        conn = None
        if self.meta.sfagent and self.meta.sfagent._cursor.connection:
            conn = self.meta.sfagent._cursor._connection

        while self.retry_count[retry_id] < self.max_retry:
            cur_timestamp = self.credentials.timestamp
            url, rest_kwargs = get_request_args()
            # rest_kwargs["timeout"] = (REQUEST_CONNECTION_TIMEOUT, REQUEST_READ_TIMEOUT)
            try:
                if conn:
                    async with conn._rest._use_requests_session(url) as session:
                        logger.debug(f"storage client request with session {session}")
                        response = await session.request(verb, url, **rest_kwargs)
                else:
                    logger.debug("storage client request with new session")
                    response = await aiohttp.ClientSession().request(
                        verb, url, **rest_kwargs
                    )

                if self._has_expired_presigned_url(response):
                    self._update_presigned_url()
                else:
                    self.last_err_is_presigned_url = False
                    if response.status in self.TRANSIENT_HTTP_ERR:
                        time.sleep(
                            min(
                                # TODO should SLEEP_UNIT come from the parent
                                #  SnowflakeConnection and be customizable by users?
                                (2 ** self.retry_count[retry_id]) * self.SLEEP_UNIT,
                                self.SLEEP_MAX,
                            )
                        )
                        self.retry_count[retry_id] += 1
                    elif await self._has_expired_token(response):
                        self.credentials.update(cur_timestamp)
                    else:
                        return response
            except self.TRANSIENT_ERRORS as e:
                self.last_err_is_presigned_url = False
                time.sleep(
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

    async def prepare_download(self) -> None:
        # TODO: add nicer error message for when target directory is not writeable
        #  but this should be done before we get here
        base_dir = os.path.dirname(self.full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        # HEAD
        file_header = await self.get_file_header(self.meta.real_src_file_name)

        if file_header and file_header.encryption_metadata:
            self.encryption_metadata = file_header.encryption_metadata

        self.num_of_chunks = 1
        if file_header and file_header.content_length:
            self.meta.src_file_size = file_header.content_length
            # only needed in big file transfer
            # if (
            #     self.chunked_transfer
            #     and self.meta.src_file_size > self.meta.multipart_threshold
            # ):
            #     self.num_of_chunks = ceil(file_header.content_length / self.chunk_size)

        # Preallocate encrypted file.
        with self.intermediate_dst_path.open("wb+") as fd:
            fd.truncate(self.meta.src_file_size)

    async def upload_chunk(self, chunk_id: int) -> None:
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
        await self._upload_chunk(chunk_id, _data)
        logger.debug(f"Successfully uploaded chunk {chunk_id} of file {self.data_file}")

    @abstractmethod
    async def _upload_chunk(self, chunk_id: int, chunk: bytes) -> None:
        pass

    @abstractmethod
    async def download_chunk(self, chunk_id: int) -> None:
        pass

    # Override in S3
    async def _initiate_multipart_upload(self) -> None:
        return

    # Override in S3
    async def _complete_multipart_upload(self) -> None:
        return

    # Override in S3
    async def _abort_multipart_upload(self) -> None:
        return

    @abstractmethod
    async def _has_expired_token(self, response: requests.Response) -> bool:
        pass
