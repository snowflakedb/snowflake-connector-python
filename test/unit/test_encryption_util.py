#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import codecs
import glob
import os
from os import path

from snowflake.connector.constants import UTF8
from snowflake.connector.encryption_util import SnowflakeEncryptionUtil
from snowflake.connector.remote_storage_util import SnowflakeFileEncryptionMaterial

from ..generate_test_files import generate_k_lines_of_n_files

THIS_DIR = path.dirname(path.realpath(__file__))


def test_encrypt_decrypt_file(tmp_path):
    """Encrypts and Decrypts a file."""
    encryption_material = SnowflakeFileEncryptionMaterial(
        query_stage_master_key="ztke8tIdVt1zmlQIZm0BMA==",
        query_id="123873c7-3a66-40c4-ab89-e3722fbccce1",
        smk_id=3112,
    )
    data = "test data"
    input_file = tmp_path / "test_encrypt_decrypt_file"
    encrypted_file = None
    decrypted_file = None
    try:
        with input_file.open("w", encoding=UTF8) as fd:
            fd.write(data)

        (metadata, encrypted_file) = SnowflakeEncryptionUtil.encrypt_file(
            encryption_material, input_file
        )
        decrypted_file = SnowflakeEncryptionUtil.decrypt_file(
            metadata, encryption_material, encrypted_file
        )

        contents = ""
        with codecs.open(decrypted_file, "r", encoding=UTF8) as fd:
            for line in fd:
                contents += line
        assert data == contents, "encrypted and decrypted contents"
    finally:
        input_file.unlink()
        if encrypted_file:
            os.remove(encrypted_file)
        if decrypted_file:
            os.remove(decrypted_file)


def test_encrypt_decrypt_large_file(tmpdir):
    """Encrypts and Decrypts a large file."""
    encryption_material = SnowflakeFileEncryptionMaterial(
        query_stage_master_key="ztke8tIdVt1zmlQIZm0BMA==",
        query_id="123873c7-3a66-40c4-ab89-e3722fbccce1",
        smk_id=3112,
    )

    # generates N files
    number_of_files = 1
    number_of_lines = 10000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = glob.glob(os.path.join(tmp_dir, "file*"))
    input_file = files[0]
    encrypted_file = None
    decrypted_file = None
    try:
        (metadata, encrypted_file) = SnowflakeEncryptionUtil.encrypt_file(
            encryption_material, input_file
        )
        decrypted_file = SnowflakeEncryptionUtil.decrypt_file(
            metadata, encryption_material, encrypted_file
        )

        contents = ""
        cnt = 0
        with codecs.open(decrypted_file, "r", encoding=UTF8) as fd:
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
