#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
import shutil
import time
from abc import abstractmethod
from logging import getLogger
from typing import TYPE_CHECKING, Tuple

from .constants import ResultStatus
from .encryption_util import SnowflakeEncryptionUtil
from .storage_client import SnowflakeStorageClient

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

DEFAULT_CONCURRENCY = 1
DEFAULT_MAX_RETRY = 5

logger = getLogger(__name__)


class NeedRenewTokenError(Exception):
    pass


class SnowflakeRemoteStorageClient(SnowflakeStorageClient):
    def __init__(self, pool, credentials):
        super().__init__()
        self.pool = pool
        self.credentials = credentials

    @abstractmethod
    def _get_file_header(self, meta: "SnowflakeFileMeta", filename: str):
        pass

    @abstractmethod
    def _native_upload_file(
        self,
        data_file: str,
        meta: "SnowflakeFileMeta",
        encryption_metadata: Tuple["EncryptionMetadata", None],
        max_concurrency: int,
        multipart_threshold: int,
    ):
        pass

    @abstractmethod
    def _native_download_file(
        self, meta: "SnowflakeFileMeta", full_dst_file_name: str, max_concurrency: int
    ):
        pass

    def _upload_file_with_retry(self, meta: "SnowflakeFileMeta") -> None:
        """Optionally encrypts and uploads a file to remote storage."""
        logger.debug(
            f"putting a file: {meta.client_meta.stage_info['location']}, {meta.dst_file_name}"
        )
        max_concurrency = meta.parallel
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            if not meta.overwrite:
                file_header = self._get_file_header(meta, meta.dst_file_name)

                if file_header and meta.result_status == ResultStatus.UPLOADED:
                    logger.debug(
                        f'file already exists location="{meta.client_meta.stage_info["location"]}", '
                        f'file_name="{meta.dst_file_name}"'
                    )
                    meta.dst_file_size = 0
                    meta.result_status = ResultStatus.SKIPPED
                    return

            if meta.overwrite or meta.result_status == ResultStatus.NOT_FOUND_FILE:
                self._native_upload_file(
                    self.data_file,
                    meta,
                    self.encryption_metadata,
                    max_concurrency,
                    multipart_threshold=meta.multipart_threshold,
                )

            if meta.result_status == ResultStatus.UPLOADED:
                return
            elif meta.result_status == ResultStatus.RENEW_PRESIGNED_URL:
                return
            elif meta.result_status == ResultStatus.NEED_RETRY:
                last_err = meta.last_error
                logger.debug(
                    f"Failed to upload a file: {self.data_file}, err: {last_err}. Retrying with "
                    f"max concurrency: {max_concurrency}"
                )
                if not meta.no_sleeping_time:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(f"sleeping {sleeping_time}")
                    time.sleep(sleeping_time)
            elif meta.result_status == ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY:
                last_err = meta.last_error
                max_concurrency = meta.parallel - int(retry * meta.parallel / max_retry)
                max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                meta.last_max_concurrency = max_concurrency

                logger.debug(
                    f"Failed to upload a file: {self.data_file}, err: {last_err}. Retrying with "
                    f"max concurrency: {max_concurrency}"
                )
                if meta.no_sleeping_time is None:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(f"sleeping: {sleeping_time}")
                    time.sleep(sleeping_time)
        else:
            self._abort_multipart_upload(meta)
            if last_err:
                raise last_err
            else:
                msg = f"Unknown Error in uploading a file: {self.data_file}"
                raise Exception(msg)

    def _abort_multipart_upload(self, meta: "SnowflakeFileMeta"):
        pass

    def _download_file(self, meta: "SnowflakeFileMeta") -> None:
        """Downloads a file from remote storage."""
        full_dst_file_name = os.path.join(
            meta.local_location, os.path.basename(meta.dst_file_name)
        )
        full_dst_file_name = os.path.realpath(full_dst_file_name)
        # TODO: validate full_dst_file_name is under the writable directory
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        file_header = self._get_file_header(meta, meta.src_file_name)

        if file_header:
            meta.src_file_size = file_header.content_length

        full_dst_file_name = os.path.join(
            meta.local_location, os.path.basename(meta.dst_file_name)
        )
        full_dst_file_name = os.path.realpath(full_dst_file_name)

        max_concurrency = meta.parallel
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            self._native_download_file(meta, full_dst_file_name, max_concurrency)
            if meta.result_status == ResultStatus.DOWNLOADED:
                if meta.encryption_material is not None:
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
                        file_header = self._get_file_header(meta, meta.src_file_name)

                    tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                        file_header.encryption_metadata,
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
                return
            elif meta.result_status == ResultStatus.RENEW_PRESIGNED_URL:
                return
            elif meta.result_status == ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY:
                max_concurrency = meta.parallel - int(retry * meta.parallel / max_retry)
                max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                meta.last_max_concurrency = max_concurrency
                last_err = meta.last_error
                logger.debug(
                    f"Failed to download a file: {full_dst_file_name}, err: {last_err}. Retrying with "
                    f"max concurrency: {max_concurrency}"
                )
                if not meta.no_sleeping_time:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug("sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
            elif meta.result_status == ResultStatus.NEED_RETRY:
                last_err = meta.last_error
                logger.debug(
                    f"Failed to download a file: {full_dst_file_name}, err: {last_err}. Retrying with "
                    f"max concurrency: {max_concurrency}"
                )
                if not meta.no_sleeping_time:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(f"sleeping: {sleeping_time}")
                    time.sleep(sleeping_time)
        else:
            if last_err:
                raise last_err
            else:
                msg = f"Unknown Error in downloading a file: {full_dst_file_name}"
                raise Exception(msg)
