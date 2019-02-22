#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
import shutil
import time
from collections import namedtuple
from logging import getLogger

from .azure_util import SnowflakeAzureUtil
from .constants import (SHA256_DIGEST, ResultStatus)
from .encryption_util import (SnowflakeEncryptionUtil)
from .s3_util import SnowflakeS3Util

DEFAULT_CONCURRENCY = 1
DEFAULT_MAX_RETRY = 5

"""
Encryption Material
"""
SnowflakeFileEncryptionMaterial = namedtuple(
    "SnowflakeS3FileEncryptionMaterial", [
        "query_stage_master_key",  # query stage master key
        "query_id",  # query id
        "smk_id"  # SMK id
    ]
)


class NeedRenewTokenError(Exception):
    pass


class SnowflakeRemoteStorageUtil(object):

    @staticmethod
    def getStorageType(type):
        if (type == u'S3'):
            return SnowflakeS3Util
        elif (type == u'AZURE'):
            return SnowflakeAzureUtil

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False):
        util_class = SnowflakeRemoteStorageUtil.getStorageType(
            stage_info[u'locationType'])
        return util_class.create_client(
            stage_info,
            use_accelerate_endpoint=use_accelerate_endpoint)

    @staticmethod
    def upload_one_file_to_s3(meta):
        """
        Uploads a file to S3
        :param meta: a file meta
        """
        logger = getLogger(__name__)
        encryption_metadata = None

        if u'encryption_material' in meta:
            (encryption_metadata,
             data_file) = SnowflakeEncryptionUtil.encrypt_file(
                meta[u'encryption_material'],
                meta[u'real_src_file_name'], tmp_dir=meta[u'tmp_dir'])

            logger.debug(
                u'encrypted data file=%s, size=%s', data_file,
                os.path.getsize(data_file))
        else:
            logger.debug(u'not encrypted data file')
            data_file = meta[u'real_src_file_name']
        util_class = SnowflakeRemoteStorageUtil.getStorageType(
            meta[u'stage_info'][u'locationType'])
        if not meta.get(u'overwrite'):
            file_header = util_class.get_file_header(
                meta, meta[u'dst_file_name'])
            if meta[u'result_status'] == ResultStatus.RENEW_TOKEN:
                # need renew token
                return
            elif file_header and meta[
                u'result_status'] == ResultStatus.UPLOADED and \
                    not meta.get(u'overwrite'):
                logger.debug(
                    u'file already exists, checking digest: '
                    u'location="%s", file_name="%s"',
                    meta[u'stage_info'][u'location'],
                    meta[u'dst_file_name'])
                sfc_digest = file_header.digest
                if sfc_digest == meta[SHA256_DIGEST]:
                    logger.debug(u'file digest matched: digest=%s',
                                 sfc_digest)
                    meta[u'dst_file_size'] = 0
                    meta[u'error_details'] = \
                        (u'File with the same destination name '
                         u'and checksum already exists')
                    meta[u'result_status'] = ResultStatus.SKIPPED
                    return
                else:
                    logger.debug(
                        u"file digest didn't match: digest_s3=%s, "
                        u"digest_local=%s",
                        sfc_digest, meta[SHA256_DIGEST])

        logger.debug(u'putting a file: %s, %s',
                     meta[u'stage_info'][u'location'], meta[u'dst_file_name'])

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            util_class.upload_file(
                data_file,
                meta,
                encryption_metadata,
                max_concurrency
            )

            if (meta[u'result_status'] == ResultStatus.UPLOADED):
                return
            elif (meta[u'result_status'] == ResultStatus.RENEW_TOKEN):
                return
            elif (meta[u'result_status'] == ResultStatus.NEED_RETRY):
                last_err = meta[u'last_error']
                logger.debug(
                    'Failed to upload a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    data_file, last_err, max_concurrency)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
            elif (meta[
                      u'result_status'] == ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY):
                last_err = meta[u'last_error']
                max_concurrency = meta[u'parallel'] - int(
                    retry * meta[u'parallel'] / max_retry)
                max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                meta['last_max_concurrency'] = max_concurrency

                logger.debug(
                    'Failed to upload a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    data_file, last_err, max_concurrency)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
        else:
            if last_err:
                raise last_err
            else:
                raise Exception(
                    "Unknown Error in uploading a file: %s",
                    data_file)

    @staticmethod
    def download_one_file(meta):
        """
        Downloads a file from S3
        :param meta: file meta
        """
        logger = getLogger(__name__)
        full_dst_file_name = os.path.join(
            meta[u'local_location'],
            os.path.basename(meta[u'dst_file_name']))
        full_dst_file_name = os.path.realpath(full_dst_file_name)
        # TODO: validate full_dst_file_name is under the writable directory
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        util_class = SnowflakeRemoteStorageUtil.getStorageType(
            meta[u'stage_info'][u'locationType'])
        file_header = util_class.get_file_header(meta, meta[u'src_file_name'])
        meta[u'src_file_size'] = file_header.content_length

        full_dst_file_name = os.path.join(
            meta[u'local_location'],
            os.path.basename(meta[u'dst_file_name']))
        full_dst_file_name = os.path.realpath(full_dst_file_name)

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            util_class._native_download_file(meta, full_dst_file_name,
                                             max_concurrency)
            if (meta[u'result_status'] == ResultStatus.DOWNLOADED):
                if u'encryption_material' in meta:
                    logger.debug(
                        u'encrypted data file=%s', full_dst_file_name)
                    tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                        file_header.encryption_metadata,
                        meta[u'encryption_material'],
                        full_dst_file_name, tmp_dir=meta[u'tmp_dir'])
                    shutil.copyfile(tmp_dst_file_name, full_dst_file_name)
                    os.unlink(tmp_dst_file_name)
                else:
                    logger.debug(u'not encrypted data file=%s',
                                 full_dst_file_name)

                statinfo = os.stat(full_dst_file_name)
                meta[u'dst_file_size'] = statinfo.st_size
                return
            elif (meta[u'result_status'] == ResultStatus.RENEW_TOKEN):
                return
            elif (meta[
                      u'result_status'] == ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY):
                max_concurrency = meta[u'parallel'] - int(
                    retry * meta[u'parallel'] / max_retry)
                max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                meta['last_max_concurrency'] = max_concurrency
                last_err = meta[u'last_error']
                logger.debug(
                    'Failed to download a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    full_dst_file_name, last_err, max_concurrency)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
            elif (meta[u'result_status'] == ResultStatus.NEED_RETRY):
                last_err = meta[u'last_error']
                logger.debug(
                    'Failed to download a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    full_dst_file_name, last_err, max_concurrency)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
        else:
            if last_err:
                raise last_err
            else:
                raise Exception(
                    "Unknown Error in downloading a file: %s",
                    full_dst_file_name)

    @staticmethod
    def upload_one_file_with_retry(meta):
        """
        Uploads one file to S3 with retry
        :param meta: a file meta
        """
        logger = getLogger(__name__)

        util_class = SnowflakeRemoteStorageUtil.getStorageType(
            meta[u'stage_info'][u'locationType'])
        for _ in range(10):
            # retry
            SnowflakeRemoteStorageUtil.upload_one_file_to_s3(meta)
            if meta[u'result_status'] == ResultStatus.UPLOADED:
                for _ in range(10):
                    util_class.get_file_header(
                        meta, meta[u'dst_file_name'])
                    if meta[u'result_status'] == ResultStatus.NOT_FOUND_FILE:
                        time.sleep(1)  # wait 1 second
                        logger.debug('not found. double checking...')
                        continue
                    break
                else:
                    # not found. retry with the outer loop
                    logger.debug('not found. gave up. reuploading...')
                    continue
            break
        else:
            # could not upload a file even after retry
            meta[u'result_status'] = ResultStatus.ERROR
