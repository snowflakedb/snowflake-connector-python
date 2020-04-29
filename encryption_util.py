#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#


import base64
import json
import os
import tempfile
from collections import namedtuple
from logging import getLogger

from Cryptodome.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD, TO_UNICODE
from .constants import UTF8

block_size = int(algorithms.AES.block_size / 8)  # in bytes


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
                     chunk_size=block_size * 4 * 1024, tmp_dir=None):
        """
        Encrypts a file
        :param encryption_material: encryption material
        :param in_filename: input file name
        :param chunk_size: read chunk size
        :param tmp_dir: temporary directory, optional
        :return: a encrypted file
        """
        logger = getLogger(__name__)
        use_openssl_only = os.getenv('SF_USE_OPENSSL_ONLY', 'False') == 'True'
        decoded_key = base64.standard_b64decode(
            encryption_material.query_stage_master_key)
        key_size = len(decoded_key)
        logger.debug(u'key_size = %s', key_size)

        # Generate key for data encryption
        iv_data = SnowflakeEncryptionUtil.get_secure_random(block_size)
        file_key = SnowflakeEncryptionUtil.get_secure_random(key_size)
        if not use_openssl_only:
            data_cipher = AES.new(key=file_key, mode=AES.MODE_CBC, IV=iv_data)
        else:
            backend = default_backend()
            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv_data), backend=backend)
            encryptor = cipher.encryptor()

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
                    elif len(chunk) % block_size != 0:
                        chunk = PKCS5_PAD(chunk, block_size)
                        padded = True
                    if not use_openssl_only:
                        outfile.write(data_cipher.encrypt(chunk))
                    else:
                        outfile.write(encryptor.update(chunk))
                if not padded:
                    if not use_openssl_only:
                        outfile.write(data_cipher.encrypt(
                            block_size * chr(block_size).encode(UTF8)))
                    else:
                        outfile.write(encryptor.update(
                            block_size * chr(block_size).encode(UTF8)))
                if use_openssl_only:
                    outfile.write(encryptor.finalize())

        # encrypt key with QRMK
        if not use_openssl_only:
            key_cipher = AES.new(key=decoded_key, mode=AES.MODE_ECB)
            enc_kek = key_cipher.encrypt(PKCS5_PAD(file_key, block_size))
        else:
            cipher = Cipher(algorithms.AES(decoded_key), modes.ECB(), backend=backend)
            encryptor = cipher.encryptor()
            enc_kek = encryptor.update(PKCS5_PAD(file_key, block_size)) + encryptor.finalize()

        mat_desc = MaterialDescriptor(
            smk_id=encryption_material.smk_id,
            query_id=encryption_material.query_id,
            key_size=key_size * 8)
        metadata = EncryptionMetadata(
            key=base64.b64encode(enc_kek).decode('utf-8'),
            iv=base64.b64encode(iv_data).decode('utf-8'),
            matdesc=matdesc_to_unicode(mat_desc),
        )
        return metadata, temp_output_file

    @staticmethod
    def decrypt_file(metadata, encryption_material, in_filename,
                     chunk_size=block_size * 4 * 1024, tmp_dir=None):
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
        use_openssl_only = os.getenv('SF_USE_OPENSSL_ONLY', 'False') == 'True'
        key_base64 = metadata.key
        iv_base64 = metadata.iv
        decoded_key = base64.standard_b64decode(
            encryption_material.query_stage_master_key)
        key_bytes = base64.standard_b64decode(key_base64)
        iv_bytes = base64.standard_b64decode(iv_base64)

        if not use_openssl_only:
            key_cipher = AES.new(key=decoded_key, mode=AES.MODE_ECB)
            file_key = PKCS5_UNPAD(key_cipher.decrypt(key_bytes))
            data_cipher = AES.new(key=file_key, mode=AES.MODE_CBC, IV=iv_bytes)
        else:
            backend = default_backend()
            cipher = Cipher(algorithms.AES(decoded_key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()
            file_key = PKCS5_UNPAD(decryptor.update(key_bytes) + decryptor.finalize())
            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv_bytes), backend=backend)
            decryptor = cipher.decryptor()

        temp_output_fd, temp_output_file = tempfile.mkstemp(
            text=False, dir=tmp_dir,
            prefix=os.path.basename(in_filename) + "#")
        total_file_size = 0
        prev_chunk = None
        logger.debug(u'encrypted file: %s, tmp file: %s',
                     in_filename, temp_output_file)
        with open(in_filename, u'rb') as infile:
            with os.fdopen(temp_output_fd, u'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    total_file_size += len(chunk)
                    if not use_openssl_only:
                        d = data_cipher.decrypt(chunk)
                    else:
                        d = decryptor.update(chunk)
                    outfile.write(d)
                    prev_chunk = d
                if prev_chunk is not None:
                    total_file_size -= PKCS5_OFFSET(prev_chunk)
                if use_openssl_only:
                    outfile.write(decryptor.finalize())
                outfile.truncate(total_file_size)
        return temp_output_file
