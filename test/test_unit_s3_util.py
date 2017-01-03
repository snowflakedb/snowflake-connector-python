#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import codecs
import glob
import os
import tempfile

from snowflake.connector.constants import UTF8
from snowflake.connector.s3_util import SnowflakeS3Util, \
    SnowflakeS3FileEncryptionMaterial


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
