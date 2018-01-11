#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#


import base64

from logging import getLogger
import json
from Crypto.Cipher import AES
import os
import tempfile
from collections import namedtuple
from .compat import (PKCS5_PAD, PKCS5_UNPAD, PKCS5_OFFSET, TO_UNICODE)
from .constants import UTF8


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
Metadata for encrpytion
"""
EncryptionMetadata = namedtuple(
    "EncryptionMetadata", [
        "key",
        "iv",
        "matdesc"
    ]
)


class SnowflakeEncryptionUtil(object):
    @staticmethod
    def get_secure_random(byte_length):
        return os.urandom(byte_length)

    @staticmethod
    def encrypt_file(encryption_material, in_filename,
                     chunk_size=AES.block_size * 4 * 1024, tmp_dir=None):
        """
        Encrypts a file
        :param s3_metadata: S3 metadata output
        :param encryption_material: encryption material
        :param in_filename: input file name
        :param chunk_size: read chunk size
        :param tmp_dir: temporary directory, optional
        :return: a encrypted file
        """
        logger = getLogger(__name__)
        decoded_key = base64.standard_b64decode(
            encryption_material.query_stage_master_key)
        key_size = len(decoded_key)
        logger.debug(u'key_size = %s', key_size)

        # Generate key for data encryption
        iv_data = SnowflakeEncryptionUtil.get_secure_random(AES.block_size)
        file_key = SnowflakeEncryptionUtil.get_secure_random(key_size)
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
        metadata = EncryptionMetadata(
            key=base64.b64encode(enc_kek).decode('utf-8'),
            iv=base64.b64encode(iv_data).decode('utf-8'),
            matdesc=matdesc_to_unicode(mat_desc),
        )
        return (metadata, temp_output_file)

    @staticmethod
    def decrypt_file(metadata, encryption_material, in_filename,
                     chunk_size=AES.block_size * 4 * 1024, tmp_dir=None):
        """
        Decrypts a file and stores the output in the temporary directory
        :param metadata: metadata input
        :param encryption_material: encryption material
        :param in_filename: input file name
        :param chunk_size: read chunk size
        :param tmp_dir: temporary directory, optional
        :return: a decrypted file name
        """
        logger = getLogger(__name__)
        key_base64 = metadata.key
        iv_base64 = metadata.iv
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
