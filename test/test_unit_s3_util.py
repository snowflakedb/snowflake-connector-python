#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import errno
import os
from collections import defaultdict
from os import path

import botocore
import OpenSSL
from boto3.exceptions import S3UploadFailedError
from mock import MagicMock, Mock, PropertyMock

from snowflake.connector.constants import SHA256_DIGEST, ResultStatus
from snowflake.connector.remote_storage_util import DEFAULT_MAX_RETRY, SnowflakeRemoteStorageUtil
from snowflake.connector.s3_util import ERRORNO_WSAECONNABORTED, SnowflakeS3Util

THIS_DIR = path.dirname(path.realpath(__file__))


def test_extract_bucket_name_and_path():
    """Extracts bucket name and S3 path."""
    s3_util = SnowflakeS3Util

    s3_loc = s3_util.extract_bucket_name_and_path(
        'sfc-dev1-regression/test_sub_dir/')
    assert s3_loc.bucket_name == 'sfc-dev1-regression'
    assert s3_loc.s3path == 'test_sub_dir/'

    s3_loc = s3_util.extract_bucket_name_and_path(
        'sfc-dev1-regression/stakeda/test_stg/test_sub_dir/')
    assert s3_loc.bucket_name == 'sfc-dev1-regression'
    assert s3_loc.s3path == 'stakeda/test_stg/test_sub_dir/'

    s3_loc = s3_util.extract_bucket_name_and_path(
        'sfc-dev1-regression/')
    assert s3_loc.bucket_name == 'sfc-dev1-regression'
    assert s3_loc.s3path == ''

    s3_loc = s3_util.extract_bucket_name_and_path(
        'sfc-dev1-regression//')
    assert s3_loc.bucket_name == 'sfc-dev1-regression'
    assert s3_loc.s3path == '/'

    s3_loc = s3_util.extract_bucket_name_and_path(
        'sfc-dev1-regression///')
    assert s3_loc.bucket_name == 'sfc-dev1-regression'
    assert s3_loc.s3path == '//'


def test_upload_one_file_to_s3_wsaeconnaborted():
    """Tests Upload one file to S3 with retry on ERRORNO_WSAECONNABORTED.

    Notes:
        The last attempted max_currency should be (initial_parallel/max_retry).
    """
    upload_file = MagicMock(
        side_effect=OpenSSL.SSL.SysCallError(
            ERRORNO_WSAECONNABORTED, 'mock err. connection aborted'))
    s3object = MagicMock(metadata=defaultdict(str), upload_file=upload_file)
    client = Mock()
    client.Object.return_value = s3object
    initial_parallel = 100
    upload_meta = {
        'no_sleeping_time': True,
        'parallel': initial_parallel,
        'put_callback': None,
        'put_callback_output_stream': None,
        'existing_files': [],
        'client': client,
        SHA256_DIGEST: '123456789abcdef',
        'stage_info': {
            'location': 'sfc-customer-stage/rwyi-testacco/users/9220/',
            'locationType': 'S3',
        },
        'dst_file_name': 'data1.txt.gz',
        'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
        'overwrite': True,
    }
    upload_meta['real_src_file_name'] = upload_meta['src_file_name']
    upload_meta['upload_size'] = os.stat(upload_meta['src_file_name']).st_size
    tmp_upload_meta = upload_meta.copy()
    try:
        SnowflakeRemoteStorageUtil.upload_one_file(tmp_upload_meta)
        raise Exception("Should fail with OpenSSL.SSL.SysCallError")
    except OpenSSL.SSL.SysCallError:
        assert upload_file.call_count == DEFAULT_MAX_RETRY
        assert 'last_max_concurrency' in tmp_upload_meta
        assert tmp_upload_meta[
                   'last_max_concurrency'
               ] == initial_parallel / DEFAULT_MAX_RETRY

    # min parallel == 1
    upload_file.reset_mock()
    initial_parallel = 4
    upload_meta['parallel'] = initial_parallel
    tmp_upload_meta = upload_meta.copy()
    try:
        SnowflakeRemoteStorageUtil.upload_one_file(tmp_upload_meta)
        raise Exception("Should fail with OpenSSL.SSL.SysCallError")
    except OpenSSL.SSL.SysCallError:
        assert upload_file.call_count == DEFAULT_MAX_RETRY
        assert 'last_max_concurrency' in tmp_upload_meta
        assert tmp_upload_meta['last_max_concurrency'] == 1


def test_upload_one_file_to_s3_econnreset():
    """Tests Upload one file to S3 with retry on errno.ECONNRESET.

    Notes:
        The last attempted max_currency should not be changed.
    """
    for error_code in [errno.ECONNRESET,
                       errno.ETIMEDOUT,
                       errno.EPIPE,
                       -1]:
        upload_file = MagicMock(
            side_effect=OpenSSL.SSL.SysCallError(
                error_code, 'mock err. connection aborted'))
        s3object = MagicMock(metadata=defaultdict(str), upload_file=upload_file)
        client = Mock()
        client.Object.return_value = s3object
        initial_parallel = 100
        upload_meta = {
            'no_sleeping_time': True,
            'parallel': initial_parallel,
            'put_callback': None,
            'put_callback_output_stream': None,
            'existing_files': [],
            SHA256_DIGEST: '123456789abcdef',
            'stage_info': {
                'location': 'sfc-teststage/rwyitestacco/users/1234/',
                'locationType': 'S3',
            },
            'client': client,
            'dst_file_name': 'data1.txt.gz',
            'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
            'overwrite': True,
        }
        upload_meta['real_src_file_name'] = upload_meta['src_file_name']
        upload_meta[
            'upload_size'] = os.stat(upload_meta['src_file_name']).st_size
        try:
            SnowflakeRemoteStorageUtil.upload_one_file(upload_meta)
            raise Exception("Should fail with OpenSSL.SSL.SysCallError")
        except OpenSSL.SSL.SysCallError:
            assert upload_file.call_count == DEFAULT_MAX_RETRY
            assert 'last_max_concurrency' not in upload_meta


def test_get_s3_file_object_http_400_error():
    """Tests Get S3 file object with HTTP 400 error.

    Looks like HTTP 400 is returned when AWS token expires and S3.Object.load is called.
    """
    load_method = MagicMock(
        side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': '400', 'Message': 'Bad Request'}},
            operation_name='mock load'))
    s3object = MagicMock(load=load_method)
    client = Mock()
    client.Object.return_value = s3object
    client.load.return_value = None
    type(client).s3path = PropertyMock(return_value='s3://testbucket/')
    meta = {
        'client': client,
        'stage_info': {
            'location': 'sfc-teststage/rwyitestacco/users/1234/',
            'locationType': 'S3',
        }
    }
    filename = "/path1/file2.txt"
    akey = SnowflakeS3Util.get_file_header(meta, filename)
    assert akey is None
    assert meta['result_status'] == ResultStatus.RENEW_TOKEN


def test_upload_file_with_s3_upload_failed_error():
    """Tests Upload file with S3UploadFailedError, which could indicate AWS token expires."""
    upload_file = MagicMock(
        side_effect=S3UploadFailedError(
            "An error occurred (ExpiredToken) when calling the "
            "CreateMultipartUpload operation: The provided token has expired."))
    client = Mock()
    client.Object.return_value = MagicMock(
        metadata=defaultdict(str), upload_file=upload_file)
    initial_parallel = 100
    upload_meta = {
        'no_sleeping_time': True,
        'parallel': initial_parallel,
        'put_callback': None,
        'put_callback_output_stream': None,
        'existing_files': [],
        SHA256_DIGEST: '123456789abcdef',
        'stage_info': {
            'location': 'sfc-teststage/rwyitestacco/users/1234/',
            'locationType': 'S3',
        },
        'client': client,
        'dst_file_name': 'data1.txt.gz',
        'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
        'overwrite': True,
    }
    upload_meta['real_src_file_name'] = upload_meta['src_file_name']
    upload_meta[
        'upload_size'] = os.stat(upload_meta['src_file_name']).st_size

    akey = SnowflakeRemoteStorageUtil.upload_one_file(upload_meta)
    assert akey is None
    assert upload_meta['result_status'] == ResultStatus.RENEW_TOKEN
