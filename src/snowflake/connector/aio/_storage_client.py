from __future__ import annotations

import asyncio
import os
import shutil
from abc import abstractmethod
from logging import getLogger
from math import ceil
from typing import TYPE_CHECKING, Any, Callable

import aiohttp
import OpenSSL

from ..constants import FileHeader, ResultStatus
from ..encryption_util import SnowflakeEncryptionUtil
from ..errors import RequestExceedMaxRetryError
from ..storage_client import SnowflakeStorageClient as SnowflakeStorageClientSync
from ._session_manager import SessionManagerFactory

if TYPE_CHECKING:  # pragma: no cover
    from ..file_transfer_agent import SnowflakeFileMeta, StorageCredential

logger = getLogger(__name__)


class SnowflakeStorageClient(SnowflakeStorageClientSync):
    TRANSIENT_ERRORS = (OpenSSL.SSL.SysCallError, asyncio.TimeoutError, ConnectionError)

    def __init__(
        self,
        meta: SnowflakeFileMeta,
        stage_info: dict[str, Any],
        chunk_size: int,
        chunked_transfer: bool | None = True,
        credentials: StorageCredential | None = None,
        max_retry: int = 5,
        unsafe_file_write: bool = False,
    ) -> None:
        SnowflakeStorageClientSync.__init__(
            self,
            meta=meta,
            stage_info=stage_info,
            chunk_size=chunk_size,
            chunked_transfer=chunked_transfer,
            credentials=credentials,
            max_retry=max_retry,
            unsafe_file_write=unsafe_file_write,
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
            # multi-chunk file transfer
            self.num_of_chunks = ceil(meta.upload_size / self.chunk_size)

        logger.debug(f"number of chunks {self.num_of_chunks}")
        # clean up
        self.retry_count = {}

        for chunk_id in range(self.num_of_chunks):
            self.retry_count[chunk_id] = 0
        # multi-chunk file transfer
        if self.chunked_transfer and self.num_of_chunks > 1:
            await self._initiate_multipart_upload()

    async def finish_upload(self) -> None:
        meta = self.meta
        if self.successful_transfers == self.num_of_chunks and self.num_of_chunks != 0:
            # multi-chunk file transfer
            if self.num_of_chunks > 1:
                await self._complete_multipart_upload()
            meta.result_status = ResultStatus.UPLOADED
            meta.dst_file_size = meta.upload_size
            logger.debug(f"{meta.src_file_name} upload is completed.")
        else:
            # TODO: add more error details to result/meta
            meta.dst_file_size = 0
            logger.debug(f"{meta.src_file_name} upload is aborted.")
            # multi-chunk file transfer
            if self.num_of_chunks > 1:
                await self._abort_multipart_upload()
            meta.result_status = ResultStatus.ERROR

    async def finish_download(self) -> None:
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
                    file_header = await self.get_file_header(meta.src_file_name)
                    self.encryption_metadata = file_header.encryption_metadata

                tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                    self.encryption_metadata,
                    meta.encryption_material,
                    str(self.intermediate_dst_path),
                    tmp_dir=self.tmp_dir,
                    unsafe_file_write=self.unsafe_file_write,
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

    async def _send_request_with_retry(
        self,
        verb: str,
        get_request_args: Callable[[], tuple[str, dict[str, Any]]],
        retry_id: int,
    ) -> aiohttp.ClientResponse:
        url = ""
        conn = None
        if self.meta.sfagent and self.meta.sfagent._cursor.connection:
            conn = self.meta.sfagent._cursor._connection

        while self.retry_count[retry_id] < self.max_retry:
            logger.debug(f"retry #{self.retry_count[retry_id]}")
            cur_timestamp = self.credentials.timestamp
            url, rest_kwargs = get_request_args()
            # rest_kwargs["timeout"] = (REQUEST_CONNECTION_TIMEOUT, REQUEST_READ_TIMEOUT)
            try:
                if conn:
                    async with conn.rest.use_session(url=url) as session:
                        logger.debug(f"storage client request with session {session}")
                        response = await session.request(verb, url, **rest_kwargs)
                else:
                    # This path should be entered only in unusual scenarios - when entrypoint to transfer wasn't through
                    # connection -> cursor. It is rather unit-tests-specific use case. Due to this fact we can create
                    # SessionManager on the fly, if code ends up here, since we probably do not care about losing
                    # proxy or HTTP setup.
                    logger.debug("storage client request with new session")
                    session_manager = SessionManagerFactory.get_manager(
                        use_pooling=False
                    )
                    response = await session_manager.request(verb, url, **rest_kwargs)

                if await self._has_expired_presigned_url(response):
                    logger.debug(
                        "presigned url expired. trying to update presigned url."
                    )
                    await self._update_presigned_url()
                else:
                    self.last_err_is_presigned_url = False
                    if response.status in self.TRANSIENT_HTTP_ERR:
                        logger.debug(f"transient error: {response.status}")
                        await asyncio.sleep(
                            min(
                                # TODO should SLEEP_UNIT come from the parent
                                #  SnowflakeConnection and be customizable by users?
                                (2 ** self.retry_count[retry_id]) * self.SLEEP_UNIT,
                                self.SLEEP_MAX,
                            )
                        )
                        self.retry_count[retry_id] += 1
                    elif await self._has_expired_token(response):
                        logger.debug("token is expired. trying to update token")
                        self.credentials.update(cur_timestamp)
                        self.retry_count[retry_id] += 1
                    else:
                        return response
            except self.TRANSIENT_ERRORS as e:
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
            # multi-chunk file transfer
            if (
                self.chunked_transfer
                and self.meta.src_file_size > self.meta.multipart_threshold
            ):
                self.num_of_chunks = ceil(file_header.content_length / self.chunk_size)

        # Preallocate encrypted file.
        with self._open_intermediate_dst_path("wb+") as fd:
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

    # Override in GCS
    async def _has_expired_presigned_url(
        self, response: aiohttp.ClientResponse
    ) -> bool:
        return False

    # Override in GCS
    async def _update_presigned_url(self) -> None:
        return

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
    async def _has_expired_token(self, response: aiohttp.ClientResponse) -> bool:
        pass
