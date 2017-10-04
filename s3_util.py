#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import errno
import os
import shutil
import time
from collections import namedtuple
from logging import getLogger

import OpenSSL
import boto3
import botocore.exceptions
from boto3.exceptions import RetriesExceededError, S3UploadFailedError
from boto3.s3.transfer import TransferConfig
from botocore.client import Config

from .compat import TO_UNICODE
from .constants import (AMZ_MATDESC, AMZ_KEY, AMZ_IV,
                        SFC_DIGEST, SHA256_DIGEST)
from .encryption_util import (SnowflakeEncryptionUtil, EncryptionMetadata)

RESULT_STATUS_ERROR = u'ERROR'
RESULT_STATUS_UPLOADED = u'UPLOADED'
RESULT_STATUS_DOWNLOADED = u'DOWNLOADED'
RESULT_STATUS_COLLISION = u'COLLISION'
RESULT_STATUS_SKIPPED = u'SKIPPED'
RESULT_STATUS_RENEW_TOKEN = u'RENEW_TOKEN'
RESULT_STATUS_NOT_FOUND_FILE = u'NOT_FOUND_FILE'

DEFAULT_CONCURRENCY = 1
DEFAULT_MAX_RETRY = 5
ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

EXPIRED_TOKEN = u'ExpiredToken'

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", [
        "bucket_name",  # S3 bucket name
        "s3path"  # S3 path name

    ])

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


class SnowflakeS3Util(object):
    """
    S3 Utility class
    """
    # magic number, given from the AWS error message.
    DATA_SIZE_THRESHOLD = 5242880

    @staticmethod
    def create_client(stage_credentials, use_accelerate_endpoint=False):
        """
        Creates a client object with a stage credential
        :param stage_credentials: a stage credential
        :param use_accelerate_endpoint: is accelerate endpoint?
        :return: client
        """
        logger = getLogger(__name__)
        security_token = stage_credentials[
            u'AWS_TOKEN'] if u'AWS_TOKEN' in stage_credentials else None
        logger.debug(u"AWS_ID: %s", stage_credentials[u'AWS_ID'])

        config = Config(
            signature_version=u's3v4',
            s3={
                'use_accelerate_endpoint': use_accelerate_endpoint,
            })
        client = boto3.resource(
            u's3',
            region_name=stage_credentials['region'],
            aws_access_key_id=stage_credentials[u'AWS_ID'],
            aws_secret_access_key=stage_credentials[u'AWS_KEY'],
            aws_session_token=security_token,
            config=config,
        )
        return client

    @staticmethod
    def upload_one_file_to_s3(meta):
        """
        Uploads a file to S3
        :param meta: a file meta
        """
        logger = getLogger(__name__)
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            meta[u'stage_location'])
        s3path = s3location.s3path + meta[u'dst_file_name']
        s3_metadata = {
            u'Content-Type': u'application/octet-stream',
            SFC_DIGEST: meta[SHA256_DIGEST],
        }
        if u'encryption_material' in meta:
            (metadata, data_file) = SnowflakeEncryptionUtil.encrypt_file(
                meta[u'encryption_material'],
                meta[u'real_src_file_name'], tmp_dir=meta[u'tmp_dir'])
            s3_metadata.update({
                AMZ_IV: metadata.iv,
                AMZ_KEY: metadata.key,
                AMZ_MATDESC: metadata.matdesc,
            })
            logger.debug(
                u'encrypted data file=%s, size=%s', data_file,
                os.path.getsize(data_file))
        else:
            logger.debug(u'not encrypted data file')
            data_file = meta[u'real_src_file_name']

        akey = SnowflakeS3Util.get_s3_file_object(meta, meta[u'dst_file_name'])
        if meta[u'result_status'] == RESULT_STATUS_RENEW_TOKEN:
            # need renew token
            return
        elif akey and meta[u'result_status'] == RESULT_STATUS_UPLOADED and \
                not meta.get(u'overwrite'):
            logger.info(
                u'file already exists, checking digest: file=%s', s3path)
            try:
                sfc_digest = akey.metadata[SFC_DIGEST]
                if sfc_digest == meta[SHA256_DIGEST]:
                    logger.info(u'file digest matched: digest=%s',
                                sfc_digest)
                    meta[u'dst_file_size'] = 0
                    meta[u'error_details'] = \
                        (u'File with the same destination name '
                         u'and checksum already exists')
                    meta[u'result_status'] = RESULT_STATUS_SKIPPED
                    return
                else:
                    logger.info(
                        (u"file digest didn't match: "
                         u"digest_s3=%s, digest_local=%s"),
                        sfc_digest, meta[SHA256_DIGEST])
            except botocore.exceptions.ClientError as e:
                # this could happen in the last minute
                if e.response[u'Error'][u'Code'] != '404':
                    raise e
                logger.debug(u'ignored. file not found: %s, %s',
                             s3location.bucket_name, s3path)

        logger.debug(u'putting a file: %s', s3path)
        put_callback = meta[u'put_callback']
        put_callback_output_stream = meta[u'put_callback_output_stream']

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            try:
                akey.upload_file(
                    data_file,
                    Callback=put_callback(
                        data_file,
                        os.path.getsize(data_file),
                        output_stream=put_callback_output_stream) if \
                        put_callback else None,
                    ExtraArgs={
                        u'Metadata': s3_metadata,
                        u'ContentEncoding': u'gzip',
                    },
                    Config=TransferConfig(
                        multipart_threshold=SnowflakeS3Util.DATA_SIZE_THRESHOLD,
                        max_concurrency=max_concurrency,
                        num_download_attempts=10,
                    )
                )
                break
            except botocore.exceptions.ClientError as err:
                if err.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                    logger.debug(u"AWS Token expired. Renew and retry")
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                logger.debug(
                    u"Failed to upload a file: %s, err: %s",
                    data_file, err, exc_info=True)
                raise err
            except S3UploadFailedError as err:
                if EXPIRED_TOKEN in TO_UNICODE(err):
                    # Since AWS token expiration error can be encapsulated in
                    # S3UploadFailedError, the text match is required to
                    # identify the case.
                    logger.debug(
                        'Failed to upload a file: %s, err: %s. Renewing '
                        'AWS Token and Retrying',
                        data_file, err)
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                last_err = err
                logger.info(
                    'Failed to upload a file: %s, err: %s. Retrying',
                    data_file, err)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
            except OpenSSL.SSL.SysCallError as err:
                last_err = err
                if err.args[0] not in (
                        ERRORNO_WSAECONNABORTED,
                        errno.ECONNRESET,
                        errno.ETIMEDOUT,
                        errno.EPIPE,
                        -1):
                    raise err
                if err.args[0] == ERRORNO_WSAECONNABORTED:
                    # connection was disconnected by S3
                    # because of too many connections. retry with
                    # less concurrency to mitigate it
                    max_concurrency = meta[u'parallel'] - int(
                        retry * meta[u'parallel'] / max_retry)
                    max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                    meta['last_max_concurrency'] = max_concurrency
                logger.info(
                    'Failed to upload a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    data_file, err, max_concurrency)
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

        logger.debug(u'DONE putting a file')
        meta[u'dst_file_size'] = meta[u'upload_size']
        meta[u'result_status'] = RESULT_STATUS_UPLOADED

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

        get_callback = meta[u'get_callback']
        get_callback_output_stream = meta[u'get_callback_output_stream']

        akey = SnowflakeS3Util.get_s3_file_object(meta, meta[u'src_file_name'])
        meta[u'src_file_size'] = akey.content_length

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            try:
                akey.download_file(
                    full_dst_file_name,
                    Callback=get_callback(
                        meta[u'src_file_name'],
                        meta[u'src_file_size'],
                        output_stream=get_callback_output_stream) if \
                        get_callback else None,
                    Config=TransferConfig(
                        multipart_threshold=SnowflakeS3Util.DATA_SIZE_THRESHOLD,
                        max_concurrency=max_concurrency,
                        num_download_attempts=10,
                    )
                )
                break
            except botocore.exceptions.ClientError as err:
                if err.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                    logger.debug(u"AWS Token expired. Renew and retry")
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                logger.debug(
                    u"Failed to download a file: %s, err: %s",
                    full_dst_file_name, err, exc_info=True)
                raise err
            except RetriesExceededError as err:
                last_err = err
                logger.debug(
                    'Failed to download a file: %s, err: %s. Retrying',
                    full_dst_file_name, err)
                if 'no_sleeping_time' not in meta:
                    sleeping_time = min(2 ** retry, 16)
                    logger.debug(u"sleeping: %s", sleeping_time)
                    time.sleep(sleeping_time)
            except OpenSSL.SSL.SysCallError as err:
                last_err = err
                if err.args[0] not in (
                        ERRORNO_WSAECONNABORTED,
                        errno.ECONNRESET,
                        errno.ETIMEDOUT,
                        errno.EPIPE,
                        -1):
                    raise err
                if err.args[0] == ERRORNO_WSAECONNABORTED:
                    # connection was disconnected by S3
                    # because of too many connections. retry with
                    # less concurrency to mitigate it
                    max_concurrency = meta[u'parallel'] - int(
                        retry * meta[u'parallel'] / max_retry)
                    max_concurrency = max(DEFAULT_CONCURRENCY, max_concurrency)
                    meta['last_max_concurrency'] = max_concurrency
                logger.info(
                    'Failed to download a file: %s, err: %s. Retrying with '
                    'max concurrency: %s',
                    full_dst_file_name, err, max_concurrency)
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

        if u'encryption_material' in meta:
            logger.debug(
                u'encrypted data file=%s', full_dst_file_name)
            metadata = EncryptionMetadata(
                key=akey.metadata[AMZ_KEY],
                iv=akey.metadata[AMZ_IV],
                matdesc=None,
            )
            tmp_dst_file_name = SnowflakeEncryptionUtil.decrypt_file(
                metadata, meta[u'encryption_material'],
                full_dst_file_name, tmp_dir=meta[u'tmp_dir'])
            shutil.copyfile(tmp_dst_file_name, full_dst_file_name)
            os.unlink(tmp_dst_file_name)
        else:
            logger.debug(u'not encrypted data file=%s',
                         full_dst_file_name)

        statinfo = os.stat(full_dst_file_name)
        meta[u'dst_file_size'] = statinfo.st_size

    @staticmethod
    def extract_bucket_name_and_path(stage_location):
        bucket_name = stage_location
        s3path = u''

        # split stage location as bucket name and path
        if u'/' in stage_location:
            bucket_name = stage_location[0:stage_location.index(u'/')]
            s3path = stage_location[stage_location.index(u'/') + 1:]
            if s3path and not s3path.endswith(u'/'):
                s3path += u'/'

        return S3Location(
            bucket_name=bucket_name,
            s3path=s3path)

    @staticmethod
    def get_s3_file_object(meta, filename):
        """
        Gets S3 file object
        :param meta: file meta object
        :return: S3 object if no error, otherwise None. Check meta[
        u'result_status'] for status.
        """
        import logging
        logger = getLogger(__name__)
        client = meta[u'client']
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            meta[u'stage_location'])
        s3path = s3location.s3path + filename.lstrip('/')

        if logger.getEffectiveLevel() == logging.DEBUG:
            tmp_meta = {}
            for k, v in meta.items():
                if k != 'stage_credentials':
                    tmp_meta[k] = v
            logger.debug(
                u"s3location.bucket_name: %s, "
                u"s3location.s3path: %s, "
                u"s3fullpath: %s, "
                u'meta: %s',
                s3location.bucket_name,
                s3location.s3path,
                s3path, tmp_meta)

        try:
            # HTTP HEAD request
            akey = client.Object(s3location.bucket_name, s3path)
            akey.load()
        except botocore.exceptions.ClientError as e:
            if e.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                logger.debug(u"AWS Token expired. Renew and retry")
                meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                return None
            elif e.response[u'Error'][u'Code'] == u'404':
                logger.debug(u'not found. bucket: %s, path: %s',
                             s3location.bucket_name, s3path)
                meta[u'result_status'] = RESULT_STATUS_NOT_FOUND_FILE
                return akey
            elif e.response[u'Error'][u'Code'] == u'400':
                logger.debug(u'Bad request, token needs to be renewed: %s. '
                             u'bucket: %s, path: %s',
                             e.response[u'Error'][u'Message'],
                             s3location.bucket_name, s3path)
                meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                return None
            logger.debug(
                u"Failed to get metadata for %s, %s: %s",
                s3location.bucket_name, s3path, e)
            meta[u'result_status'] = RESULT_STATUS_ERROR
            return None

        meta[u'result_status'] = RESULT_STATUS_UPLOADED
        return akey

    @staticmethod
    def upload_one_file_with_retry(meta):
        """
        Uploads one file to S3 with retry
        :param meta: a file meta
        """
        logger = getLogger(__name__)
        for _ in range(10):
            # retry
            SnowflakeS3Util.upload_one_file_to_s3(meta)
            if meta[u'result_status'] == RESULT_STATUS_UPLOADED:
                for _ in range(10):
                    _ = SnowflakeS3Util.get_s3_file_object(
                        meta, meta[u'dst_file_name'])
                    if meta[u'result_status'] == RESULT_STATUS_NOT_FOUND_FILE:
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
            meta[u'result_status'] = RESULT_STATUS_ERROR
