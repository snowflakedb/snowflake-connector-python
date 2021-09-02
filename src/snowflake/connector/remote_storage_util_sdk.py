#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
import shutil
import time
from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, NamedTuple

from boto3 import Session

from .azure_util_sdk import SnowflakeAzureUtil
from .constants import ResultStatus
from .encryption_util import SnowflakeEncryptionUtil
from .gcs_util_sdk import SnowflakeGCSUtil
from .s3_util_sdk import SnowflakeS3Util

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent_sdk import SnowflakeFileMeta

DEFAULT_CONCURRENCY = 1
DEFAULT_MAX_RETRY = 5

logger = getLogger(__name__)


class SnowflakeFileEncryptionMaterial(NamedTuple):
    query_stage_master_key: str  # query stage master key
    query_id: str  # query id
    smk_id: int  # SMK id


class NeedRenewTokenError(Exception):
    pass


class SnowflakeRemoteStorageUtil(object):
    @staticmethod
    def get_for_storage_type(_type):
        if _type == "S3":
            return SnowflakeS3Util
        elif _type == "AZURE":
            return SnowflakeAzureUtil
        elif _type == "GCS":
            return SnowflakeGCSUtil
        else:
            return None

    @staticmethod
    def create_client(
        stage_info,
        use_accelerate_endpoint: bool = False,
        use_s3_regional_url: bool = False,
        s3_connection_pool_size: int = 1,
    ) -> Session.resource:
        util_class = SnowflakeRemoteStorageUtil.get_for_storage_type(
            stage_info["locationType"]
        )
        return util_class.create_client(
            stage_info,
            use_accelerate_endpoint=use_accelerate_endpoint,
            use_s3_regional_url=use_s3_regional_url,
            s3_connection_pool_size=s3_connection_pool_size,
        )

    @staticmethod
    def upload_one_file(meta: "SnowflakeFileMeta") -> None:
        """Uploads a file to S3."""
        encryption_metadata = None

        if meta.encryption_material is not None:
            if meta.src_stream is None:
                (encryption_metadata, data_file) = SnowflakeEncryptionUtil.encrypt_file(
                    meta.encryption_material,
                    meta.real_src_file_name,
                    tmp_dir=meta.tmp_dir,
                )
                logger.debug(
                    f"encrypted data file={data_file}, size={os.path.getsize(data_file)}"
                )
            else:
                encrypted_stream = BytesIO()
                src_stream = meta.real_src_stream or meta.src_stream
                src_stream.seek(0)
                encryption_metadata = SnowflakeEncryptionUtil.encrypt_stream(
                    meta.encryption_material, src_stream, encrypted_stream
                )
                src_stream.seek(0)
                logger.debug(
                    f"encrypted data stream size={encrypted_stream.seek(0, os.SEEK_END)}"
                )
                encrypted_stream.seek(0)
                if meta.real_src_stream is not None:
                    meta.real_src_stream.close()
                meta.real_src_stream = encrypted_stream
                data_file = meta.real_src_file_name
        else:
            logger.debug("not encrypted data file")
            data_file = meta.real_src_file_name

        util_class = SnowflakeRemoteStorageUtil.get_for_storage_type(
            meta.client_meta.stage_info["locationType"]
        )

        logger.debug(
            f"putting a file: {meta.client_meta.stage_info['location']}, {meta.dst_file_name}"
        )

        max_concurrency = meta.parallel
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            if not meta.overwrite:
                file_header = util_class.get_file_header(meta, meta.dst_file_name)

                if file_header and meta.result_status == ResultStatus.UPLOADED:
                    logger.debug(
                        f'file already exists location="{meta.client_meta.stage_info["location"]}", '
                        f'file_name="{meta.dst_file_name}"'
                    )
                    meta.dst_file_size = 0
                    meta.result_status = ResultStatus.SKIPPED
                    return

            if meta.overwrite or meta.result_status == ResultStatus.NOT_FOUND_FILE:
                util_class.upload_file(
                    data_file,
                    meta,
                    encryption_metadata,
                    max_concurrency,
                    multipart_threshold=meta.multipart_threshold,
                )

            if meta.result_status == ResultStatus.UPLOADED:
                return
            elif meta.result_status == ResultStatus.RENEW_TOKEN:
                return
            elif meta.result_status == ResultStatus.RENEW_PRESIGNED_URL:
                return
            elif meta.result_status == ResultStatus.NEED_RETRY:
                last_err = meta.last_error
                logger.debug(
                    f"Failed to upload a file: {data_file}, err: {last_err}. Retrying with "
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
                    f"Failed to upload a file: {data_file}, err: {last_err}. Retrying with "
                    f"max concurrency: {max_concurrency}"
                )
                if meta.no_sleeping_time is None:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(f"sleeping: {sleeping_time}")
                    time.sleep(sleeping_time)
        else:
            if last_err:
                raise last_err
            else:
                msg = f"Unknown Error in uploading a file: {data_file}"
                raise Exception(msg)

    @staticmethod
    def download_one_file(meta: "SnowflakeFileMeta") -> None:
        """Downloads a file from S3."""
        full_dst_file_name = os.path.join(
            meta.local_location, os.path.basename(meta.dst_file_name)
        )
        full_dst_file_name = os.path.realpath(full_dst_file_name)
        # TODO: validate full_dst_file_name is under the writable directory
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        util_class = SnowflakeRemoteStorageUtil.get_for_storage_type(
            meta.client_meta.stage_info["locationType"]
        )
        file_header = util_class.get_file_header(meta, meta.src_file_name)

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
            util_class._native_download_file(meta, full_dst_file_name, max_concurrency)
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
                        file_header = util_class.get_file_header(
                            meta, meta.src_file_name
                        )

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
            elif meta.result_status == ResultStatus.RENEW_TOKEN:
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

    @staticmethod
    def upload_one_file_with_retry(meta: "SnowflakeFileMeta") -> None:
        """Uploads one file with retry."""
        util_class = SnowflakeRemoteStorageUtil.get_for_storage_type(
            meta.client_meta.stage_info["locationType"]
        )
        for _ in range(10):
            # retry
            SnowflakeRemoteStorageUtil.upload_one_file(meta)
            if meta.result_status == ResultStatus.UPLOADED:
                for _ in range(10):
                    util_class.get_file_header(meta, meta.dst_file_name)
                    if meta.result_status == ResultStatus.NOT_FOUND_FILE:
                        time.sleep(1)  # wait 1 second
                        logger.debug("not found. double checking...")
                        continue
                    break
                else:
                    # not found. retry with the outer loop
                    logger.debug("not found. gave up. re-uploading...")
                    continue
            break
        else:
            # could not upload a file even after retry
            meta.result_status = ResultStatus.ERROR
