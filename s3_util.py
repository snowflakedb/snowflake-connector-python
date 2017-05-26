#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import base64
import errno
import gzip
import json
import os
import shutil
import struct
import tempfile
import time
from collections import namedtuple
from io import open
from logging import getLogger

import OpenSSL
import boto3
import botocore.exceptions
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from boto3.exceptions import RetriesExceededError, S3UploadFailedError
from boto3.s3.transfer import TransferConfig
from botocore.client import Config

from .compat import (PKCS5_PAD, PKCS5_UNPAD, PKCS5_OFFSET, TO_UNICODE)
from .constants import (AMZ_MATDESC, AMZ_KEY, AMZ_IV,
                        SFC_DIGEST, SHA256_DIGEST, UTF8)

RESULT_STATUS_ERROR = u'ERROR'
RESULT_STATUS_UPLOADED = u'UPLOADED'
RESULT_STATUS_DOWNLOADED = u'DOWNLOADED'
RESULT_STATUS_COLLISION = u'COLLISION'
RESULT_STATUS_SKIPPED = u'SKIPPED'
RESULT_STATUS_RENEW_TOKEN = u'RENEW_TOKEN'

DEFAULT_CONCURRENCY = 1
DEFAULT_MAX_RETRY = 5
ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", [
        "bucket_name",  # S3 bucket name
        "s3path"  # S3 path name

    ])

"""
Material Description
"""
MaterialDescriptor = namedtuple(
    "MaterialDescriptor", [
        "smk_id",  # SMK id
        "query_id",  # query id
        "key_size"  # key size, 128 or 256
    ]
)

"""
Encryption Material
"""
SnowflakeS3FileEncryptionMaterial = namedtuple(
    "SnowflakeS3FileEncryptionMaterial", [
        "query_stage_master_key",  # query stage master key
        "query_id",  # query id
        "smk_id"  # SMK id
    ]
)


def matdesc_to_unicode(matdesc):
    """
    Convert Material Descriptor to Unicode String
    """
    return TO_UNICODE(
        json.dumps({
            u'queryId': matdesc.query_id,
            u'smkId': str(matdesc.smk_id),
            u'keySize': str(matdesc.key_size)
        },
            separators=(',', ':')))


class SnowflakeS3Util(object):
    """
    S3 Utility class
    """
    # magic number, given from the AWS error message.
    DATA_SIZE_THRESHOLD = 5242880

    @staticmethod
    def create_s3_client(stage_credentials, use_accelerate_endpoint=False):
        logger = getLogger(__name__)
        security_token = stage_credentials[
            u'AWS_TOKEN'] if u'AWS_TOKEN' in stage_credentials else None
        logger.debug(u"AWS_ID: %s", stage_credentials[u'AWS_ID'])

        config = Config(
            signature_version=u's3v4',
            s3={
                'use_accelerate_endpoint': use_accelerate_endpoint,
            })
        s3client = boto3.resource(
            u's3',
            region_name=stage_credentials['region'],
            aws_access_key_id=stage_credentials[u'AWS_ID'],
            aws_secret_access_key=stage_credentials[u'AWS_KEY'],
            aws_session_token=security_token,
            config=config,
        )
        return s3client

    @staticmethod
    def upload_one_file_to_s3(meta):
        logger = getLogger(__name__)
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            meta[u'stage_location'])
        s3client = meta[u's3client']
        s3path = s3location.s3path + meta[u'dst_file_name']
        logger.debug(
            u"meta['stage_location']=[%s], "
            u"s3location.bucket_name=[%s], "
            u"s3location.s3path=[%s], "
            u"meta[dst_file_name]=[%s], "
            u"s3path=[%s], "
            u"meta['src_file_name']=[%s], "
            u"meta['src_file_name'].size()=[%s], "
            u"meta['real src file name']=[%s], "
            u"meta['real src file name'].size()=[%s]",
            meta[u'stage_location'],
            s3location.bucket_name,
            s3location.s3path,
            meta[u'dst_file_name'],
            s3path,
            meta[u'src_file_name'],
            os.path.getsize(meta[u'src_file_name']),
            meta[u'real_src_file_name'],
            os.path.getsize(meta[u'real_src_file_name'])
        )
        s3_metadata = {
            u'Content-Type': u'application/octet-stream',
            SFC_DIGEST: meta[SHA256_DIGEST],
        }
        if u'encryption_material' in meta:
            data_file = SnowflakeS3Util.encrypt_file(
                s3_metadata, meta[u'encryption_material'],
                meta[u'real_src_file_name'], tmp_dir=meta[u'tmp_dir'])
            size = os.path.getsize(data_file)
            logger.debug(
                u'encrypted data file=%s, size=%s', data_file, size)
        else:
            logger.debug(u'not encrypted data file')
            data_file = meta[u'real_src_file_name']

        if s3path in meta[u'existing_files']:
            logger.info(
                u'file already exists, checking digest: file=%s',
                s3path)
            try:
                akey = s3client.Object(s3location.bucket_name, s3path)
            except botocore.exceptions.ClientError as e:
                if e.response[u'Error'][u'Code'] == u'ExpiredToken':
                    logger.debug(u"AWS Token expired. Renew and retry")
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                logger.debug(
                    u"Failed to get metadata for %s, %s: %s",
                    s3location.bucket_name, s3path, e)
                raise e

            if akey:
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
                    if e.response[u'Error'][u'Code'] != '404':
                        raise e
                    logger.debug(u'ignored. file not found: %s, %s',
                                 s3location.bucket_name, s3path)

            else:
                logger.info(
                    u'file has gone. file: file=%s', s3path)

        logger.debug(u'setting a new key: file=%s', s3path)

        logger.debug(u'putting a file')
        put_callback = meta[u'put_callback']
        put_callback_output_stream = meta[u'put_callback_output_stream']

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            try:
                s3client.meta.client.upload_file(
                    data_file, s3location.bucket_name, s3path,
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
                if err.response[u'Error'][u'Code'] == u'ExpiredToken':
                    logger.debug(u"AWS Token expired. Renew and retry")
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                logger.exception(
                    u"Failed to upload a file: %s, err: %s",
                    data_file, err)
                raise err
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
            except S3UploadFailedError as err:
                last_err = err
                logger.info(
                    'Failed to upload a file: %s, err: %s. Retrying',
                    data_file, err)
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
    def download_one_file_from_s3(meta):
        logger = getLogger(__name__)
        full_dst_file_name = os.path.join(
            meta[u'local_location'],
            os.path.basename(meta[u'dst_file_name']))
        full_dst_file_name = os.path.realpath(full_dst_file_name)
        # TODO: validate full_dst_file_name is under the writable directory
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            meta[u'stage_location'])

        s3client = meta[u's3client']
        # NOTE: src_file_name may include '/' in the beginning, e.g.,
        #       /data1.txt.gz
        #       but the sub directory name can be included:
        #       a/data1.txt.gz
        #       Since s3location.s3path always ends with '/'
        #       if not empty, extra '/' in the beginning of src_file_name
        #       must be removed.
        #       This could be done by GS end as improvement.
        s3path = s3location.s3path + meta[u'src_file_name'].lstrip('/')
        logger.debug(
            u"meta['stage_location']=[%s], "
            u"s3location.bucket_name=[%s], "
            u"s3location.s3path=[%s], "
            u"meta['src_file_name']=[%s], "
            u"s3path=[%s], "
            u"full_dst_file_name=[%s]",
            meta[u'stage_location'],
            s3location.bucket_name,
            s3location.s3path,
            meta[u'src_file_name'],
            s3path,
            full_dst_file_name)

        get_callback = meta[u'get_callback']
        get_callback_output_stream = meta[u'get_callback_output_stream']

        max_concurrency = meta[u'parallel']
        last_err = None
        max_retry = DEFAULT_MAX_RETRY
        for retry in range(max_retry):
            try:
                s3client.meta.client.download_file(
                    s3location.bucket_name, s3path, full_dst_file_name,
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
                if err.response[u'Error'][u'Code'] == u'ExpiredToken':
                    logger.debug(u"AWS Token expired. Renew and retry")
                    meta[u'result_status'] = RESULT_STATUS_RENEW_TOKEN
                    return
                logger.exception(
                    u"Failed to download a file: %s, err: %s",
                    full_dst_file_name, err)
                raise err
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
            except RetriesExceededError as err:
                last_err = err
                logger.info(
                    'Failed to download a file: %s, err: %s. Retrying',
                    full_dst_file_name, err)
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
            akey = s3client.Object(s3location.bucket_name, s3path)
            logger.debug(
                u'encrypted data file=%s', full_dst_file_name)
            s3_metadata = {
                AMZ_KEY: akey.metadata[AMZ_KEY],
                AMZ_IV: akey.metadata[AMZ_IV],
            }
            tmp_dst_file_name = SnowflakeS3Util.decrypt_file(
                s3_metadata, meta[u'encryption_material'],
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
    def get_secure_random(byte_length):
        return os.urandom(byte_length)

    @staticmethod
    def encrypt_file(s3_metadata, encryption_material, in_filename,
                     chunk_size=AES.block_size * 4 * 1024, tmp_dir=None):
        logger = getLogger(__name__)
        decoded_key = base64.standard_b64decode(
            encryption_material.query_stage_master_key)
        key_size = len(decoded_key)
        logger.debug(u'key_size = %s', key_size)

        # Generate key for data encryption
        iv_data = SnowflakeS3Util.get_secure_random(AES.block_size)
        file_key = SnowflakeS3Util.get_secure_random(key_size)
        data_cipher = AES.new(key=file_key, mode=AES.MODE_CBC, IV=iv_data)

        temp_output_fd, temp_output_file = tempfile.mkstemp(
            text=False, dir=tmp_dir,
            prefix=os.path.basename(in_filename) + "#")
        padded = False
        logger.debug(u'unencrypted file: %s, temp file: %s, tmp_dir: %s',
                     in_filename, temp_output_file, tmp_dir)
        with open(in_filename, u'rb') as infile:
            with os.fdopen(temp_output_fd, u'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % AES.block_size != 0:
                        chunk = PKCS5_PAD(chunk, AES.block_size)
                        padded = True
                    outfile.write(data_cipher.encrypt(chunk))
                if not padded:
                    outfile.write(data_cipher.encrypt(
                        AES.block_size * chr(AES.block_size).encode(UTF8)))

        # encrypt key with QRMK
        key_cipher = AES.new(key=decoded_key, mode=AES.MODE_ECB)
        enc_kek = key_cipher.encrypt(PKCS5_PAD(file_key, AES.block_size))

        mat_desc = MaterialDescriptor(
            smk_id=encryption_material.smk_id,
            query_id=encryption_material.query_id,
            key_size=key_size * 8)
        s3_metadata[AMZ_MATDESC] = matdesc_to_unicode(mat_desc)
        s3_metadata[AMZ_KEY] = base64.b64encode(enc_kek).decode('utf-8')
        s3_metadata[AMZ_IV] = base64.b64encode(iv_data).decode('utf-8')
        return temp_output_file

    @staticmethod
    def decrypt_file(s3_metadata, encryption_material, in_filename,
                     chunk_size=AES.block_size * 4 * 1024, tmp_dir=None):
        logger = getLogger(__name__)
        key_base64 = s3_metadata[AMZ_KEY]
        iv_base64 = s3_metadata[AMZ_IV]

        decoded_key = base64.standard_b64decode(
            encryption_material.query_stage_master_key)
        key_bytes = base64.standard_b64decode(key_base64)
        iv_bytes = base64.standard_b64decode(iv_base64)

        key_cipher = AES.new(key=decoded_key, mode=AES.MODE_ECB)
        file_key = PKCS5_UNPAD(key_cipher.decrypt(key_bytes))

        data_cipher = AES.new(key=file_key, mode=AES.MODE_CBC, IV=iv_bytes)

        temp_output_fd, temp_output_file = tempfile.mkstemp(
            text=False, dir=tmp_dir,
            prefix=os.path.basename(in_filename) + "#")
        total_file_size = 0
        prev_chunk = None
        logger.info(u'encrypted file: %s, tmp file: %s',
                    in_filename, temp_output_file)
        with open(in_filename, u'rb') as infile:
            with os.fdopen(temp_output_fd, u'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    total_file_size += len(chunk)
                    d = data_cipher.decrypt(chunk)
                    outfile.write(d)
                    prev_chunk = d
                if prev_chunk is not None:
                    total_file_size -= PKCS5_OFFSET(prev_chunk)
                outfile.truncate(total_file_size)
        return temp_output_file

    @staticmethod
    def compress_file_with_gzip(file_name, tmp_dir):
        logger = getLogger(__name__)
        base_name = os.path.basename(file_name)
        gzip_file_name = os.path.join(tmp_dir, base_name + u'_c.gz')
        logger.debug(u'gzip file: %s, original file: %s', gzip_file_name,
                    file_name)
        fr = open(file_name, u'rb')
        fw = gzip.GzipFile(gzip_file_name, u'wb')
        shutil.copyfileobj(fr, fw)
        fw.close()
        fr.close()
        SnowflakeS3Util.normalize_gzip_header(gzip_file_name)

        statinfo = os.stat(gzip_file_name)
        return gzip_file_name, statinfo.st_size

    @staticmethod
    def normalize_gzip_header(gzip_file_name):
        logger = getLogger(__name__)
        with open(gzip_file_name, u'r+b') as f:
            # reset the timestamp in gzip header
            f.seek(4, 0)
            f.write(struct.pack('<L', 0))
            # reset the file name in gzip header
            f.seek(10, 0)
            byte = f.read(1)
            while byte:
                value = struct.unpack('B', byte)[0]
                # logger.debug(u'ch=%s, byte=%s', value, byte)
                if value == 0:
                    break
                f.seek(-1, 1)  # current_pos - 1
                f.write(struct.pack('B', 0x20))  # replace with a space
                byte = f.read(1)

    @staticmethod
    def get_digest_and_size_for_file(file_name):
        CHUNK_SIZE = 16 * 4 * 1024
        f = open(file_name, 'rb')
        m = SHA256.new()
        while True:
            chunk = f.read(CHUNK_SIZE)
            if chunk == b'':
                break
            m.update(chunk)

        statinfo = os.stat(file_name)
        file_size = statinfo.st_size
        digest = base64.standard_b64encode(m.digest()).decode(UTF8)
        logger = getLogger(__name__)
        logger.debug(u'getting digest and size: %s, %s, file=%s', digest,
                    file_size, file_name)
        return digest, file_size

    @staticmethod
    def filter_existing_files_s3(s3client, stage_location, file_prefix):
        u"""
        List of target files
        """
        existing_files = {}
        logger = getLogger(__name__)
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            stage_location)
        s3bucket = s3client.Bucket(s3location.bucket_name)
        s3prefix = s3location.s3path + file_prefix
        logger.debug(u's3path=[%s], file_prefix=[%s], listing=[%s]',
                     s3location.s3path, file_prefix.lstrip('/'), s3prefix)
        for obj in s3bucket.objects.filter(Prefix=s3prefix, Delimiter=u'/'):
            logger.debug(u'object: %s', obj)
            existing_files[obj.key] = obj.size
        return existing_files
