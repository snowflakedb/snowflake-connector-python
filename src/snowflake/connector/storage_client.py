#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from collections import namedtuple
from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, Tuple

from .constants import ResultStatus
from .encryption_util import SnowflakeEncryptionUtil
from .file_util import SnowflakeFileUtil

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

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


class SnowflakeStorageClient(ABC):
    def __init__(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.data_file = None
        self.encryption_metadata = None

    def compress_file(self, meta: "SnowflakeFileMeta") -> None:
        logger.debug(f"compressing file={meta.src_file_name}")
        if meta.src_stream is None:
            (
                meta.real_src_file_name,
                upload_size,
            ) = SnowflakeFileUtil.compress_file_with_gzip(
                meta.src_file_name, self.tmp_dir
            )
        else:
            (
                meta.real_src_stream,
                upload_size,
            ) = SnowflakeFileUtil.compress_with_gzip_from_stream(meta.src_stream)

    @staticmethod
    def get_file_digest(meta: "SnowflakeFileMeta") -> None:
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

    def encrypt_file(
        self, meta: "SnowflakeFileMeta"
    ) -> Tuple["SnowflakeFileEncryptionMaterial", str]:
        """Optionally encrypts and uploads a file to remote storage."""
        if meta.src_stream is None:
            (encryption_metadata, data_file) = SnowflakeEncryptionUtil.encrypt_file(
                meta.encryption_material,
                meta.real_src_file_name,
                tmp_dir=self.tmp_dir,
            )
            meta.upload_size = os.path.getsize(data_file)
            return encryption_metadata, data_file
        else:
            encrypted_stream = BytesIO()
            src_stream = meta.real_src_stream or meta.src_stream
            src_stream.seek(0)
            encryption_metadata = SnowflakeEncryptionUtil.encrypt_stream(
                meta.encryption_material, src_stream, encrypted_stream
            )
            src_stream.seek(0)
            meta.upload_size = encrypted_stream.seek(0, os.SEEK_END)
            encrypted_stream.seek(0)
            if meta.real_src_stream is not None:
                meta.real_src_stream.close()
            meta.real_src_stream = encrypted_stream
            return encryption_metadata, meta.real_src_file_name

    def upload_file(self, meta: "SnowflakeFileMeta") -> "SnowflakeFileMeta":
        meta.real_src_file_name = meta.src_file_name
        meta.upload_size = meta.src_file_size
        meta.tmp_dir = self.tmp_dir
        try:
            if meta.require_compress:
                logger.debug(f"compressing file={meta.src_file_name}")
                self.compress_file(meta)

            logger.debug(f"getting digest file={meta.real_src_file_name}")
            self.get_file_digest(meta)

            if meta.encryption_material:
                self.encryption_metadata, self.data_file = self.encrypt_file(meta)
            else:
                self.data_file = meta.real_src_file_name

            self._upload_file_with_retry(meta)
            logger.debug(
                f"done: status={meta.result_status}, file={meta.src_file_name}, real file={meta.real_src_file_name}"
            )
        except Exception as e:
            logger.exception(
                f"Failed to upload a file: file={meta.src_file_name}, real file={meta.real_src_file_name}"
            )
            meta.dst_file_size = 0
            if meta.result_status is None:
                meta.result_status = ResultStatus.ERROR
            meta.error_details = str(e)
            meta.error_details += (
                f", file={meta.src_file_name}, real file={meta.real_src_file_name}"
            )
        finally:
            logger.debug(f"cleaning up tmp dir: {self.tmp_dir}")
            shutil.rmtree(self.tmp_dir)
            if meta.src_stream is not None:
                meta.src_stream.seek(0)
            if meta.real_src_stream is not None:
                meta.real_src_stream.close()
        return meta

    def download_file(self, meta: "SnowflakeFileMeta") -> "SnowflakeFileMeta":
        meta.tmp_dir = self.tmp_dir
        try:
            self._download_file(meta)
            logger.debug(
                f"done: status={meta.result_status}, file={meta.dst_file_name}"
            )
        except Exception as e:
            logger.exception(f"Failed to download a file: {meta.dst_file_name}")
            meta.dst_file_size = -1
            if meta.result_status is not None:
                meta.result_status = ResultStatus.ERROR
            meta.error_details = str(e)
            meta.error_details += f", file={meta.dst_file_name}"
        finally:
            logger.debug(f"cleaning up tmp dir: {self.tmp_dir}")
            shutil.rmtree(self.tmp_dir)
        return meta

    @abstractmethod
    def _upload_file_with_retry(self, meta: "SnowflakeFileMeta") -> None:
        pass

    @abstractmethod
    def _download_file(self, meta: "SnowflakeFileMeta") -> None:
        pass
