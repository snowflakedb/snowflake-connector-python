
from __future__ import division

import base64
import gzip
import os
import shutil
import struct
from io import open
from logging import getLogger

from Cryptodome.Hash import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from .constants import UTF8


class SnowflakeFileUtil(object):

    @staticmethod
    def compress_file_with_gzip(file_name, tmp_dir):
        """
        Compresses a file by GZIP
        :param file_name: a file name
        :param tmp_dir: temprary directory where an GZIP file will be created
        :return: a pair of gzip file name and size
        """
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
        SnowflakeFileUtil.normalize_gzip_header(gzip_file_name)

        statinfo = os.stat(gzip_file_name)
        return gzip_file_name, statinfo.st_size

    @staticmethod
    def normalize_gzip_header(gzip_file_name):
        """
        Normalize GZIP file header. For consistent file digest, this removes
        creation timestamp from the header.
        :param gzip_file_name: gzip file name
        """
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
        """
        Gets file digest and size
        :param file_name: a file name
        :return:
        """
        use_openssl_only = os.getenv('SF_USE_OPENSSL_ONLY', 'False') == 'True'
        CHUNK_SIZE = 16 * 4 * 1024
        f = open(file_name, 'rb')
        if not use_openssl_only:
            m = SHA256.new()
        else:
            backend = default_backend()
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash, backend)
        while True:
            chunk = f.read(CHUNK_SIZE)
            if chunk == b'':
                break
            if not use_openssl_only:
                m.update(chunk)
            else:
                hasher.update(chunk)

        statinfo = os.stat(file_name)
        file_size = statinfo.st_size
        if not use_openssl_only:
            digest = base64.standard_b64encode(m.digest()).decode(UTF8)
        else:
            digest = base64.standard_b64encode(hasher.finalize()).decode(UTF8)
        logger = getLogger(__name__)
        logger.debug(u'getting digest and size: %s, %s, file=%s', digest,
                     file_size, file_name)
        return digest, file_size
