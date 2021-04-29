#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
import shutil
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from collections import namedtuple
from io import BytesIO
from logging import getLogger
from math import ceil
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union

import requests
from requests import ConnectionError, Timeout

from .constants import FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata, SnowflakeEncryptionUtil
from .errors import RequestExceedMaxRetryError
from .file_util import SnowflakeFileUtil

# from .vendored.requests import Timeout, ConnectionError

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta, StorageCredential

logger = getLogger(__name__)

"""
Encryption Material
"""
SnowflakeFileEncryptionMaterial = namedtuple(
    "SnowflakeS3FileEncryptionMaterial",
    [
        "query_stage_master_key",  # query stage master key
        "query_id",  # query id
        "smk_id",  # SMK id
    ],
)

METHODS = {
    "GET": requests.get,
    "PUT": requests.put,
    "POST": requests.post,
    "HEAD": requests.head,
    "DELETE": requests.delete,
}


class SnowflakeStorageClient(ABC):
    TRANSIENT_HTTP_ERR = (408, 429, 500, 502, 503, 504)

    TRANSIENT_ERRORS = (Timeout, ConnectionError)
    SLEEP_MAX = float("inf")

    def __init__(
        self,
        meta: "SnowflakeFileMeta",
        stage_info: Dict[str, Any],
        chunk_size: int,
        chunked_transfer: Optional[bool] = True,
        credentials: Optional["StorageCredential"] = None,
    ):
        self.meta = meta
        self.stage_info = stage_info
        self.retry_count: Dict[Union[int, str], int] = {}
        self.tmp_dir = tempfile.mkdtemp()
        self.data_file: str = None
        self.encryption_metadata: "EncryptionMetadata" = None

        self.max_retry = 3  # TODO
        self.credentials = credentials
        meta.tmp_dir = self.tmp_dir
        # UPLOAD
        meta.real_src_file_name = meta.src_file_name
        meta.upload_size = meta.src_file_size
        # DOWNLOAD
        self.full_dst_file_name = ""
        # CHUNK
        self.chunked_transfer = chunked_transfer  # only true for GCS
        self.chunk_size = chunk_size
        self.num_of_chunks = 0
        self.lock = threading.Lock()
        self.successful_transfers: int = 0
        self.failed_transfers: int = 0
        self.chunks: List[bytes] = []
        # only used for PRESIGNED_URL
        self.last_err_is_presigned_url = False

    def compress(self):
        if self.meta.require_compress:
            meta = self.meta
            logger.debug(f"compressing file={meta.src_file_name}")
            if meta.src_stream:
                (
                    meta.real_src_stream,
                    upload_size,
                ) = SnowflakeFileUtil.compress_with_gzip_from_stream(meta.src_stream)
            else:
                (
                    meta.real_src_file_name,
                    upload_size,
                ) = SnowflakeFileUtil.compress_file_with_gzip(
                    meta.src_file_name, self.tmp_dir
                )

    def get_digest(self):
        meta = self.meta
        logger.debug(f"getting digest file={meta.real_src_file_name}")
        if meta.src_stream is None:
            (
                meta.sha256_digest,
                meta.upload_size,
            ) = SnowflakeFileUtil.get_digest_and_size_for_file(meta.real_src_file_name)
        else:
            (
                meta.sha256_digest,
                meta.upload_size,
            ) = SnowflakeFileUtil.get_digest_and_size_for_stream(
                meta.real_src_stream or meta.src_stream
            )

    def encrypt(self):
        meta = self.meta
        logger.debug(f"encrypting file={meta.real_src_file_name}")
        if meta.src_stream is None:
            (
                self.encryption_metadata,
                self.data_file,
            ) = SnowflakeEncryptionUtil.encrypt_file(
                meta.encryption_material,
                meta.real_src_file_name,
                tmp_dir=self.tmp_dir,
            )
            meta.upload_size = os.path.getsize(self.data_file)
        else:
            encrypted_stream = BytesIO()
            src_stream = meta.real_src_stream or meta.src_stream
            src_stream.seek(0)
            self.encryption_metadata = SnowflakeEncryptionUtil.encrypt_stream(
                meta.encryption_material, src_stream, encrypted_stream
            )
            src_stream.seek(0)
            meta.upload_size = encrypted_stream.seek(0, os.SEEK_END)
            encrypted_stream.seek(0)
            if meta.real_src_stream is not None:
                meta.real_src_stream.close()
            meta.real_src_stream = encrypted_stream
            self.data_file = meta.real_src_file_name

    @abstractmethod
    def get_file_header(self, filename: str) -> Union[FileHeader, None]:
        """Check if file exists in target location and obtain file metadata if exists.

        Notes:
            Updates meta.result_status.
        """
        pass

    def prepare_upload(self):

        logger.debug("Preparing upload")
        meta = self.meta

        self.get_file_header(meta.dst_file_name)  # Check if file exists on remote

        if meta.result_status == ResultStatus.UPLOADED and not meta.overwrite:
            # Skipped
            logger.debug(
                f'file already exists location="{self.stage_info["location"]}", '
                f'file_name="{meta.dst_file_name}"'
            )
            meta.dst_file_size = 0
            meta.result_status = ResultStatus.SKIPPED
        else:
            # Uploading
            if meta.require_compress:
                self.compress()
            self.get_digest()
            if meta.encryption_material:
                self.encrypt()
            else:
                self.data_file = meta.real_src_file_name
            logger.debug("finished preprocessing")
            if meta.upload_size < meta.multipart_threshold or not self.chunked_transfer:
                self.num_of_chunks = 1
            else:
                self.num_of_chunks = ceil(meta.upload_size / self.chunk_size)
            logger.debug(f"number of chunks {self.num_of_chunks}")
            for chunk_id in range(self.num_of_chunks):
                self.retry_count[chunk_id] = 0
            if self.chunked_transfer and self.num_of_chunks > 1:
                self._initiate_multipart_upload()

    def chunkify(self):
        meta = self.meta
        if meta.result_status == ResultStatus.SKIPPED:
            return
        if meta.src_stream:
            fd = meta.real_src_stream or meta.src_stream
            fd.seek(0)
            if self.num_of_chunks == 1:
                self.chunk_size.append(fd.read())
            else:
                for _ in range(self.num_of_chunks):
                    self.chunks.append(fd.read(self.chunk_size))

    def finish_upload(self):
        meta = self.meta
        self.chunks = []  # For garbage collection
        if self.successful_transfers == self.num_of_chunks:
            if self.num_of_chunks > 1:
                self._complete_multipart_upload()
            meta.result_status = ResultStatus.UPLOADED
            meta.dst_file_size = meta.upload_size
            logger.debug(f"{meta.src_file_name} upload is completed.")
        else:
            # TODO: add more error details to result/meta
            meta.dst_file_size = 0
            logger.debug(f"{meta.src_file_name} upload is aborted.")
            if self.num_of_chunks > 1:
                self._abort_multipart_upload()
            meta.result_status = ResultStatus.ERROR

    @abstractmethod
    def _has_expired_token(self, response: requests.Response):
        pass

    def _send_request_with_retry(
        self,
        verb: str,
        get_request_args: Callable[[], Tuple[str, Dict[str, Any]]],
        retry_id: str,
    ):
        rest_call = METHODS[verb]
        while self.retry_count[retry_id] < self.max_retry:
            cur_timestamp = self.credentials.timestamp
            url, rest_kwargs = get_request_args()
            try:
                response = rest_call(url, **rest_kwargs)
                if self._has_expired_presigned_url(response):
                    self._update_presigned_url()
                    continue
                else:
                    self.last_err_is_presigned_url = False
                    if response.status_code in self.TRANSIENT_HTTP_ERR:
                        time.sleep(
                            min((2 ** self.retry_count[retry_id]) * 100, self.SLEEP_MAX)
                        )
                        self.retry_count[retry_id] += 1
                    elif self._has_expired_token(response):
                        self.credentials.update(cur_timestamp)
                        continue
                    else:
                        return response
            except self.TRANSIENT_ERRORS:
                self.last_err_is_presigned_url = False
                time.sleep(min((2 ** self.retry_count[retry_id]) * 100, self.SLEEP_MAX))
                self.retry_count[retry_id] += 1
        else:
            raise RequestExceedMaxRetryError(
                f"{verb} with url {url} failed for exceeding maximum retries."
            )

    def prepare_download(self):
        meta = self.meta
        full_dst_file_name = os.path.join(
            meta.local_location, os.path.basename(meta.dst_file_name)
        )
        full_dst_file_name = os.path.realpath(full_dst_file_name)
        # TODO: validate full_dst_file_name is under the writable directory
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        # HEAD
        file_header = self.get_file_header(meta.dst_file_name)

        if file_header and file_header.encryption_metadata:
            self.encryption_metadata = file_header.encryption_metadata

        self.num_of_chunks = 1
        if file_header and file_header.content_length:
            meta.src_file_size = file_header.content_length
            if self.chunked_transfer and meta.src_file_size > meta.multipart_threshold:
                self.num_of_chunks = ceil(file_header.content_length / self.chunk_size)

        self.chunks = [b""] * self.num_of_chunks
        for chunk_id in range(self.num_of_chunks):
            self.retry_count[chunk_id] = 0

        self.full_dst_file_name = os.path.realpath(
            os.path.join(meta.local_location, os.path.basename(meta.dst_file_name))
        )

    def finish_download(self):
        meta = self.meta
        if self.successful_transfers == self.num_of_chunks:
            full_dst_file_name = self.full_dst_file_name

            meta.result_status = ResultStatus.DOWNLOADED
            if self.chunked_transfer:
                # TODO: workaround for gcs
                with open(self.full_dst_file_name, "wb+") as fd:
                    for chunk in self.chunks:
                        fd.write(chunk)
            self.chunks = []  # Garbage collection
            if meta.encryption_material:
                logger.debug(f"encrypted data file={full_dst_file_name}")
                # For storage utils that do not have the privilege of
                # getting the metadata early, both object and metadata
                # are downloaded at once. In which case, the file meta will
                # be updated with all the metadata that we need and
                # then we can call get_file_header to get just that and also
                # preserve the idea of getting metadata in the first place.
                # One example of this is the utils that use presigned url
                # for upload/download and not the storage client library.
                if meta.presigned_url is not None:
                    file_header = self.get_file_header(meta.src_file_name)
                    self.encryption_metadata = file_header.encryption_metadata

                tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                    self.encryption_metadata,
                    meta.encryption_material,
                    full_dst_file_name,
                    tmp_dir=meta.tmp_dir,
                )
                shutil.copyfile(tmp_dst_file_name, full_dst_file_name)
                os.unlink(tmp_dst_file_name)
            else:
                logger.debug(f"not encrypted data file={full_dst_file_name}")
            stat_info = os.stat(full_dst_file_name)
            meta.dst_file_size = stat_info.st_size
        else:
            # TODO: add more error details to result/meta
            logger.exception(f"Failed to download a file: {meta.dst_file_name}")
            meta.dst_file_size = -1
            meta.result_status = ResultStatus.ERROR

    def should_retry_on_error(self, exc: Exception) -> bool:
        return isinstance(exc, self.TRANSIENT_ERRORS) or (
            isinstance(exc, requests.HTTPError)
            and exc.response.status_code in self.TRANSIENT_HTTP_ERR
        )

    def upload_chunk(self, chunk_id: int):
        if not self.chunks:
            with open(self.data_file, "rb") as fd:
                if self.num_of_chunks == 1:
                    _data = fd.read()
                else:
                    fd.seek(chunk_id * self.chunk_size)
                    _data = fd.read(self.chunk_size)
        else:
            _data = self.chunks[chunk_id]
        logger.debug(f"Uploading chunk {chunk_id} of file {self.data_file}")
        self._upload_chunk(chunk_id, _data)
        logger.debug(f"Successfully uploaded chunk {chunk_id} of file {self.data_file}")

    @abstractmethod
    def _upload_chunk(self, chunk_id: int, chunk: bytes):
        pass

    @abstractmethod
    def download_chunk(self, chunk_id: int):
        pass

    # Override in GCS
    def _has_expired_presigned_url(self, response: requests.Response):
        return False

    # Override in GCS
    def _update_presigned_url(self):
        pass

    # Override in S3
    def _initiate_multipart_upload(self):
        pass

    # Override in S3
    def _complete_multipart_upload(self):
        pass

    # Override in S3
    def _abort_multipart_upload(self):
        pass

    def __del__(self):
        logger.debug(f"cleaning up tmp dir: {self.tmp_dir}")
        shutil.rmtree(self.tmp_dir)
        if self.meta.real_src_stream and not self.meta.real_src_stream.closed:
            self.meta.real_src_stream.close()
