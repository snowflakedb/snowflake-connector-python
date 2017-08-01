#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import codecs
import errno
import glob
import os
import tempfile
from collections import defaultdict
from os import path

import OpenSSL
import botocore

from snowflake.connector.compat import PY2
from snowflake.connector.constants import (SHA256_DIGEST, UTF8)
from snowflake.connector.s3_util import (
    SnowflakeS3Util,
    SnowflakeS3FileEncryptionMaterial,
    ERRORNO_WSAECONNABORTED, DEFAULT_MAX_RETRY,
    RESULT_STATUS_RENEW_TOKEN)

THIS_DIR = path.dirname(path.realpath(__file__))

if PY2:
    from mock import Mock, MagicMock, PropertyMock
else:
    from unittest.mock import Mock, MagicMock, PropertyMock


def test_encrypt_decrypt_file():
    """
    Encrypt and Decrypt a file
    """
    s3_util = SnowflakeS3Util()
    s3_metadata = {}

    encryption_material = SnowflakeS3FileEncryptionMaterial(
        query_stage_master_key='ztke8tIdVt1zmlQIZm0BMA==',
        query_id='123873c7-3a66-40c4-ab89-e3722fbccce1',
        smk_id=3112)
    data = 'test data'
    input_fd, input_file = tempfile.mkstemp()
    encrypted_file = None
    decrypted_file = None
    try:
        with codecs.open(input_file, 'w', encoding=UTF8) as fd:
            fd.write(data)

        encrypted_file = s3_util.encrypt_file(
            s3_metadata, encryption_material, input_file)
        decrypted_file = s3_util.decrypt_file(
            s3_metadata, encryption_material, encrypted_file)

        contents = ''
        fd = codecs.open(decrypted_file, 'r', encoding=UTF8)
        for line in fd:
            contents += line
        assert data == contents, "encrypted and decrypted contents"
    finally:
        os.close(input_fd)
        os.remove(input_file)
        if encrypted_file:
            os.remove(encrypted_file)
        if decrypted_file:
            os.remove(decrypted_file)


def test_encrypt_decrypt_large_file(tmpdir, test_files):
    """
    Encrypt and Decrypt a large file
    """
    s3_util = SnowflakeS3Util()
    s3_metadata = {}

    encryption_material = SnowflakeS3FileEncryptionMaterial(
        query_stage_master_key='ztke8tIdVt1zmlQIZm0BMA==',
        query_id='123873c7-3a66-40c4-ab89-e3722fbccce1',
        smk_id=3112)

    # generates N files
    number_of_files = 1
    number_of_lines = 10000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = glob.glob(os.path.join(tmp_dir, 'file*'))
    input_file = files[0]
    encrypted_file = None
    decrypted_file = None
    try:
        encrypted_file = s3_util.encrypt_file(
            s3_metadata, encryption_material, input_file)
        decrypted_file = s3_util.decrypt_file(
            s3_metadata, encryption_material, encrypted_file)

        contents = ''
        cnt = 0
        fd = codecs.open(decrypted_file, 'r', encoding=UTF8)
        for line in fd:
            contents += line
            cnt += 1
        assert cnt == number_of_lines, "number of lines"
    finally:
        os.remove(input_file)
        if encrypted_file:
            os.remove(encrypted_file)
        if decrypted_file:
            os.remove(decrypted_file)


def test_extract_bucket_name_and_path():
    """
    Extract bucket name and S3 path
    """
    s3_util = SnowflakeS3Util()

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
    """
    Tests Upload one file to S3 with retry on ERRORNO_WSAECONNABORTED.
    The last attempted max_currency should be (initial_parallel/max_retry)
    """
    upload_file = MagicMock(
        side_effect=OpenSSL.SSL.SysCallError(
            ERRORNO_WSAECONNABORTED, 'mock err. connection aborted'))
    s3object = MagicMock(metadata=defaultdict(str), upload_file=upload_file)
    s3client = Mock()
    s3client.Object.return_value = s3object
    initial_parallel = 100
    upload_meta = {
        u'no_sleeping_time': True,
        u'parallel': initial_parallel,
        u'put_callback': None,
        u'put_callback_output_stream': None,
        u'existing_files': [],
        u's3client': s3client,
        SHA256_DIGEST: '123456789abcdef',
        u'stage_location': 'sfc-customer-stage/rwyi-testacco/users/9220/',
        u'dst_file_name': 'data1.txt.gz',
        u'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
    }
    upload_meta[u'real_src_file_name'] = upload_meta['src_file_name']
    upload_meta[u'upload_size'] = os.stat(upload_meta['src_file_name']).st_size
    tmp_upload_meta = upload_meta.copy()
    try:
        SnowflakeS3Util.upload_one_file_to_s3(tmp_upload_meta)
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
    upload_meta[u'parallel'] = initial_parallel
    tmp_upload_meta = upload_meta.copy()
    try:
        SnowflakeS3Util.upload_one_file_to_s3(tmp_upload_meta)
        raise Exception("Should fail with OpenSSL.SSL.SysCallError")
    except OpenSSL.SSL.SysCallError:
        assert upload_file.call_count == DEFAULT_MAX_RETRY
        assert 'last_max_concurrency' in tmp_upload_meta
        assert tmp_upload_meta['last_max_concurrency'] == 1


def test_upload_one_file_to_s3_econnreset():
    """
    Tests Upload one file to S3 with retry on errno.ECONNRESET.
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
        s3client = Mock()
        s3client.Object.return_value = s3object
        initial_parallel = 100
        upload_meta = {
            u'no_sleeping_time': True,
            u'parallel': initial_parallel,
            u'put_callback': None,
            u'put_callback_output_stream': None,
            u'existing_files': [],
            SHA256_DIGEST: '123456789abcdef',
            u'stage_location': 'sfc-teststage/rwyitestacco/users/1234/',
            u's3client': s3client,
            u'dst_file_name': 'data1.txt.gz',
            u'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
        }
        upload_meta[u'real_src_file_name'] = upload_meta['src_file_name']
        upload_meta[
            u'upload_size'] = os.stat(upload_meta['src_file_name']).st_size
        try:
            SnowflakeS3Util.upload_one_file_to_s3(upload_meta)
            raise Exception("Should fail with OpenSSL.SSL.SysCallError")
        except OpenSSL.SSL.SysCallError:
            assert upload_file.call_count == DEFAULT_MAX_RETRY
            assert 'last_max_concurrency' not in upload_meta


def test_upload_one_file_to_s3_unknown_openssl_error():
    """
    Tests Upload one file to S3 with unknown OpenSSL error
    """
    for error_code in [123]:

        upload_file = MagicMock(
            side_effect=OpenSSL.SSL.SysCallError(
                error_code, 'mock err. connection aborted'))
        s3client = Mock()
        s3client.Object.return_value = MagicMock(
            metadata=defaultdict(str), upload_file=upload_file)
        initial_parallel = 100
        upload_meta = {
            u'no_sleeping_time': True,
            u'parallel': initial_parallel,
            u'put_callback': None,
            u'put_callback_output_stream': None,
            u'existing_files': [],
            SHA256_DIGEST: '123456789abcdef',
            u'stage_location': 'sfc-teststage/rwyitestacco/users/1234/',
            u's3client': s3client,
            u'dst_file_name': 'data1.txt.gz',
            u'src_file_name': path.join(THIS_DIR, 'data', 'put_get_1.txt'),
        }
        upload_meta[u'real_src_file_name'] = upload_meta['src_file_name']
        upload_meta[
            u'upload_size'] = os.stat(upload_meta['src_file_name']).st_size
        try:
            SnowflakeS3Util.upload_one_file_to_s3(upload_meta)
            raise Exception("Should fail with OpenSSL.SSL.SysCallError")
        except OpenSSL.SSL.SysCallError:
            assert upload_file.call_count == 1


def test_get_s3_file_object_http_400_error():
    """
    Tests Get S3 file object with HTTP 400 error. Looks like HTTP 400 is
    returned when AWS token expires and S3.Object.load is called.
    """
    load_method = MagicMock(
        side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': u'400', 'Message': 'Bad Request'}},
            operation_name='mock load'))
    s3object = MagicMock(load=load_method)
    s3client = Mock()
    s3client.Object.return_value = s3object
    s3client.load.return_value = None
    type(s3client).s3path = PropertyMock(return_value='s3://testbucket/')
    meta = {
        u's3client': s3client,
        u'stage_location': 'sfc-teststage/rwyitestacco/users/1234/',
    }
    filename = "/path1/file2.txt"
    akey = SnowflakeS3Util.get_s3_file_object(meta, filename)
    assert akey is None
    assert meta['result_status'] == RESULT_STATUS_RENEW_TOKEN
