#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import binascii
import glob
import mimetypes
import os
import shutil
import sys
import tempfile
import threading
from logging import getLogger
from multiprocessing.pool import ThreadPool
from time import (time, sleep)

import botocore.exceptions

from .compat import (GET_CWD, TO_UNICODE)
from .constants import (SHA256_DIGEST)
from .converter_snowsql import SnowflakeConverterSnowSQL
from .errorcode import (ER_INVALID_STAGE_FS, ER_INVALID_STAGE_LOCATION,
                        ER_LOCAL_PATH_NOT_DIRECTORY,
                        ER_FILE_NOT_EXISTS,
                        ER_COMPRESSION_NOT_SUPPORTED,
                        ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL,
                        ER_FAILED_TO_CHECK_EXISTING_FILES)
from .errors import (Error, OperationalError, InternalError, DatabaseError,
                     ProgrammingError)
from .file_compression_type import FileCompressionType
from .s3_util import (SnowflakeS3FileEncryptionMaterial, SnowflakeS3Util,
                      RESULT_STATUS_COLLISION, RESULT_STATUS_DOWNLOADED,
                      RESULT_STATUS_ERROR, RESULT_STATUS_UPLOADED,
                      RESULT_STATUS_RENEW_TOKEN)

S3_FS = u'S3'
LOCAL_FS = u'LOCAL_FS'
CMD_TYPE_UPLOAD = u'UPLOAD'
CMD_TYPE_DOWNLOAD = u'DOWNLOAD'

RESULT_TEXT_COLUMN_DESC = lambda name: {
    u'name': name, u'type': u'text',
    u'length': 16777216, u'precision': None,
    u'scale': None, u'nullable': False}
RESULT_FIXED_COLUMN_DESC = lambda name: {
    u'name': name, u'type': u'fixed',
    u'length': 5, u'precision': 0,
    u'scale': 0,
    u'nullable': False}

MB = 1024.0 * 1024.0

INJECT_WAIT_IN_PUT = 0


def _update_progress(file_name, start_time, total_size, progress,
                     output_stream):
    barLength = 10  # Modify this to change the length of the progress bar
    total_size /= MB
    status = ""
    elapsed_time = time() - start_time
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = "Done ({elapsed_time:.3f}s, {throughput:.2f}MB/s).\r\n".format(
            elapsed_time=elapsed_time,
            throughput=total_size / elapsed_time)
    if status == '':
        status = "({elapsed_time:.3f}s, {throughput:.2f}MB/s)".format(
            elapsed_time=elapsed_time,
            throughput=total_size / elapsed_time)
    block = int(round(barLength * progress))
    text = "\r{file_name}({size:.2f}MB): [{bar}] {percentage:.2f}% {status}".format(
        file_name=file_name,
        size=total_size,
        bar="#" * block + "-" * (barLength - block),
        percentage=progress * 100.0,
        status=status)
    output_stream.write(text)
    output_stream.flush()
    return progress == 1.0


class SnowflakeProgressPercentage(object):
    """
    Built-in Progress bar for PUT commands.
    """

    def __init__(self, filename, filesize, output_stream=sys.stdout):
        last_pound_char = filename.rfind('#')
        if last_pound_char < 0:
            last_pound_char = len(filename)
        self._filename = os.path.basename(filename[0:last_pound_char])
        self._output_stream = output_stream
        self._size = float(filesize)
        self._seen_so_far = 0
        self._done = False
        self._start_time = time()
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        with self._lock:
            if self._output_stream:
                self._seen_so_far += bytes_amount
                percentage = float(self._seen_so_far / self._size)
                if not self._done:
                    self._done = _update_progress(
                        self._filename, self._start_time,
                        self._size, percentage,
                        output_stream=self._output_stream)


class SnowflakeFileTransferAgent(object):
    """
    Snowflake File Transfer Agent
    """

    def __init__(self, cursor, command, ret,
                 put_callback=None,
                 put_callback_output_stream=sys.stdout,
                 get_callback=None,
                 get_callback_output_stream=sys.stdout):
        self._cursor = cursor
        self._command = command
        self._ret = ret
        self._put_callback = put_callback
        self._put_callback_output_stream = put_callback_output_stream
        self._get_callback = get_callback
        self._get_callback_output_stream = get_callback_output_stream
        self.logger = getLogger(__name__)
        self._existing_files = {}
        self._use_accelerate_endpoint = False

    def execute(self):
        self._parse_command()

        self._init_file_metadata()

        if self._command_type == CMD_TYPE_UPLOAD:
            self._process_file_compression_type()

        self._transfer_accelerate_config()

        if not self._overwrite:
            # TODO: optimize this. This won't scale
            self._filter_existing_files()

        if self._command_type == CMD_TYPE_DOWNLOAD:
            if not os.path.isdir(self._local_location):
                os.makedirs(self._local_location)

        if self._stage_location_type == LOCAL_FS:
            if not os.path.isdir(self._stage_location):
                os.makedirs(self._stage_location)

        small_file_metas = []
        large_file_metas = []
        for meta in self._file_metadata.values():
            meta[u'existing_files'] = self._existing_files
            meta[u'self'] = self
            if self._stage_location_type == S3_FS:
                meta[u'put_callback'] = self._put_callback
                meta[u'put_callback_output_stream'] = \
                    self._put_callback_output_stream
                meta[u'get_callback'] = self._get_callback
                meta[u'get_callback_output_stream'] = \
                    self._get_callback_output_stream
                if meta[
                    u'src_file_size'] > SnowflakeS3Util.DATA_SIZE_THRESHOLD:
                    meta[u'parallel'] = self._parallel
                    large_file_metas.append(meta)
                else:
                    meta[u'parallel'] = 1
                    small_file_metas.append(meta)
            else:
                meta[u'parallel'] = 1
                small_file_metas.append(meta)

        self.logger.debug(u'parallel=[%s]', self._parallel)
        self._results = []
        if self._command_type == CMD_TYPE_UPLOAD:
            self.upload(large_file_metas, small_file_metas)
        else:
            self.download(large_file_metas, small_file_metas)

    def upload(self, large_file_metas, small_file_metas):
        if self._stage_location_type == S3_FS:
            s3client = SnowflakeS3Util.create_s3_client(
                self._stage_credentials,
                use_accelerate_endpoint=self._use_accelerate_endpoint
            )
            for meta in small_file_metas:
                meta[u's3client'] = s3client
            for meta in large_file_metas:
                meta[u's3client'] = s3client

        if len(small_file_metas) > 0:
            self._upload_files_in_parallel(small_file_metas)
        if len(large_file_metas) > 0:
            self._upload_files_in_sequential(large_file_metas)

    def _transfer_accelerate_config(self):
        if self._stage_location_type == S3_FS:
            s3client = SnowflakeS3Util.create_s3_client(
                self._stage_credentials,
                use_accelerate_endpoint=False)
            s3location = SnowflakeS3Util.extract_bucket_name_and_path(
                self._stage_location
            )
            try:
                ret = s3client.meta.client.get_bucket_accelerate_configuration(
                    Bucket=s3location.bucket_name)
                self._use_accelerate_endpoint = \
                    ret and 'Status' in ret and \
                    ret['Status'] == 'Enabled'
            except botocore.exceptions.ClientError as e:
                if e.response['Error'].get('Code', 'Unknown') == \
                        'AccessDenied':
                    self.logger.debug(e)
                else:
                    # unknown error
                    self.logger.exception(e)

            self.logger.debug(
                'use_accelerate_endpoint: %s',
                self._use_accelerate_endpoint)

    def _upload_files_in_parallel(self, file_metas):
        """
        Uploads files in parallel
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            end_of_idx = idx + self._parallel if \
                idx + self._parallel <= len_file_metas else \
                len_file_metas

            self.logger.debug(
                u'uploading files idx: {0} to {1}'.format(idx, end_of_idx))

            target_meta = file_metas[idx:end_of_idx]
            while True:
                pool = ThreadPool(processes=len(target_meta))
                results = pool.map(
                    SnowflakeFileTransferAgent.upload_one_file,
                    target_meta)
                pool.close()
                pool.join()

                # need renew AWS token?
                retry_meta = []
                for result_meta in results:
                    if result_meta[
                        u'result_status'] == RESULT_STATUS_RENEW_TOKEN:
                        retry_meta.append(result_meta)
                    else:
                        self._results.append(result_meta)

                if len(retry_meta) == 0:
                    # no new AWS token is required
                    break
                s3client = self.renew_expired_aws_token()
                for result_meta in retry_meta:
                    result_meta[u's3client'] = s3client
                if end_of_idx < len_file_metas:
                    for idx0 in range(idx + self._parallel, len_file_metas):
                        file_metas[u's3client'] = s3client
                target_meta = retry_meta

            if end_of_idx == len_file_metas:
                break
            idx += self._parallel

    def _upload_files_in_sequential(self, file_metas):
        """
        Uploads files in sequential. Retry if the AWS token expires
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            result = SnowflakeFileTransferAgent.upload_one_file(
                file_metas[idx])
            if result[u'result_status'] == RESULT_STATUS_RENEW_TOKEN:
                s3client = self.renew_expired_aws_token()
                for idx0 in range(idx, len_file_metas):
                    file_metas[idx0][u's3client'] = s3client
                continue
            self._results.append(result)
            idx += 1
            if INJECT_WAIT_IN_PUT > 0:
                self.logger.debug('LONGEVITY TEST: waiting for %s',
                                  INJECT_WAIT_IN_PUT)
                sleep(INJECT_WAIT_IN_PUT)

    @staticmethod
    def upload_one_file(meta):
        """
        Upload a one file
        """
        logger = getLogger(__name__)

        logger.info(u"uploading file=%s", meta[u'src_file_name'])
        meta[u'real_src_file_name'] = meta[u'src_file_name']
        tmp_dir = tempfile.mkdtemp()
        meta[u'tmp_dir'] = tmp_dir
        try:
            if meta[u'require_compress']:
                logger.info(u'compressing file=%s', meta[u'src_file_name'])
                meta[u'real_src_file_name'], upload_size = \
                    SnowflakeS3Util.compress_file_with_gzip(
                        meta[u'src_file_name'], tmp_dir)
            logger.debug(
                u'getting digest file=%s', meta[u'real_src_file_name'])
            sha256_digest, upload_size = \
                SnowflakeS3Util.get_digest_and_size_for_file(
                    meta[u'real_src_file_name'])
            meta[SHA256_DIGEST] = sha256_digest
            meta[u'upload_size'] = upload_size

            logger.info(u'really uploading data')
            if meta[u'stage_location_type'] == LOCAL_FS:
                SnowflakeFileTransferAgent.upload_one_file_to_local(meta)
            else:  # S3
                SnowflakeS3Util.upload_one_file_to_s3(meta)
            logger.info(
                u'success: file=%s, real file=%s',
                meta[u'src_file_name'],
                meta[u'real_src_file_name'])
        except Exception as e:
            logger.exception(
                u'Failed to upload a file: file=%s, real file=%s',
                meta[u'src_file_name'],
                meta[u'real_src_file_name'])
            meta[u'dst_file_size'] = 0
            if u'result_status' not in meta:
                meta[u'result_status'] = RESULT_STATUS_ERROR
            meta[u'error_details'] = TO_UNICODE(e)
        finally:
            logger.debug(u'cleaning up tmp dir: %s', tmp_dir)
            shutil.rmtree(tmp_dir)
        return meta

    def download(self, large_file_metas, small_file_metas):
        if self._stage_location_type == S3_FS:
            s3client = SnowflakeS3Util.create_s3_client(
                self._stage_credentials,
                use_accelerate_endpoint=self._use_accelerate_endpoint)

            for meta in small_file_metas:
                meta[u's3client'] = s3client
            for meta in large_file_metas:
                meta[u's3client'] = s3client

        if len(small_file_metas) > 0:
            self._download_files_in_parallel(small_file_metas)
        if len(large_file_metas) > 0:
            self._download_files_in_sequential(large_file_metas)

    def _download_files_in_parallel(self, file_metas):
        """
        Download files in parallel
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            end_of_idx = idx + self._parallel if \
                idx + self._parallel <= len_file_metas else \
                len_file_metas

            self.logger.debug(
                'downloading files idx: {0} to {1}'.format(idx, end_of_idx))

            target_meta = file_metas[idx:end_of_idx]
            while True:
                pool = ThreadPool(processes=len(target_meta))
                results = pool.map(
                    SnowflakeFileTransferAgent.download_one_file,
                    target_meta)
                pool.close()
                pool.join()

                # need renew AWS token?
                retry_meta = []
                for result_meta in results:
                    if result_meta[
                        u'result_status'] == RESULT_STATUS_RENEW_TOKEN:
                        retry_meta.append(result_meta)
                    else:
                        self._results.append(result_meta)

                if len(retry_meta) == 0:
                    # no new AWS token is required
                    break
                s3client = self.renew_expired_aws_token()
                for result_meta in retry_meta:
                    result_meta[u's3client'] = s3client
                if end_of_idx < len_file_metas:
                    for idx0 in range(idx + self._parallel, len_file_metas):
                        file_metas[u's3client'] = s3client
                target_meta = retry_meta

            if end_of_idx == len_file_metas:
                break
            idx += self._parallel

    def _download_files_in_sequential(self, file_metas):
        """
        Downloads files in sequential. Retry if the AWS token expires
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            result = SnowflakeFileTransferAgent.download_one_file(
                file_metas[idx])
            if result[u'result_status'] == RESULT_STATUS_RENEW_TOKEN:
                s3client = self.renew_expired_aws_token()
                for idx0 in range(idx, len_file_metas):
                    file_metas[idx0][u's3client'] = s3client
                continue
            self._results.append(result)
            idx += 1
            if INJECT_WAIT_IN_PUT > 0:
                self.logger.debug('LONGEVITY TEST: waiting for %s',
                                  INJECT_WAIT_IN_PUT)
                sleep(INJECT_WAIT_IN_PUT)

    @staticmethod
    def download_one_file(meta):
        """
        Download a one file
        """
        logger = getLogger(__name__)

        tmp_dir = tempfile.mkdtemp()
        meta[u'tmp_dir'] = tmp_dir
        try:
            if meta[u'stage_location_type'] == LOCAL_FS:
                SnowflakeFileTransferAgent.download_one_file_from_local(meta)
            else:  # S3
                SnowflakeS3Util.download_one_file_from_s3(meta)

            meta[u'result_status'] = RESULT_STATUS_DOWNLOADED
        except Exception as e:
            logger.exception(u'Failed to download a file: %s',
                             meta[u'src_file_name'])
            meta[u'dst_file_size'] = -1
            if u'result_status' not in meta:
                meta[u'result_status'] = RESULT_STATUS_ERROR
            meta[u'error_details'] = TO_UNICODE(e)
        finally:
            shutil.rmtree(tmp_dir)
        return meta

    @staticmethod
    def download_one_file_from_local(meta):
        full_src_file_name = os.path.join(
            meta[u'stage_location'],
            meta[u'src_file_name'] if not meta[u'src_file_name'].startswith(
                os.sep) else
            meta[u'src_file_name'][1:])
        full_dst_file_name = os.path.join(
            meta[u'local_location'],
            os.path.basename(meta[u'dst_file_name']))
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        with open(full_src_file_name, u'rb') as frd:
            with open(full_dst_file_name, u'wb+') as output:
                output.writelines(frd)
        statinfo = os.stat(full_dst_file_name)
        meta[u'dst_file_size'] = statinfo.st_size

    @staticmethod
    def upload_one_file_to_local(meta):
        logger = getLogger(__name__)
        logger.debug(
            u"src_file_name=[%s], "
            u"real_src_file_name=[%s], "
            u"stage_location=[%s], "
            u"dst_file_name=[%s]",
            meta[u'src_file_name'],
            meta[u'real_src_file_name'],
            meta[u'stage_location'],
            meta[u'dst_file_name']
        )
        with open(meta[u'real_src_file_name'], u'rb') as frd:
            with open(os.path.join(meta[u'stage_location'],
                                   meta[u'dst_file_name']), u'wb') as output:
                output.writelines(frd)

        meta[u'dst_file_size'] = meta[u'upload_size']
        meta[u'result_status'] = RESULT_STATUS_UPLOADED

    def renew_expired_aws_token(self):
        logger = getLogger(__name__)
        logger.info(u'renewing expired aws token')
        ret = self._cursor._execute_helper(
            self._command)  # rerun the command to get the credential
        stage_credentials = ret[u'data'][u'stageInfo'][u'creds']
        return SnowflakeS3Util.create_s3_client(
            stage_credentials,
            use_accelerate_endpoint=self._use_accelerate_endpoint)

    def result(self):
        converter_class = self._cursor._connection.converter_class
        rowset = []
        if self._command_type == CMD_TYPE_UPLOAD:
            if hasattr(self, u'_results'):
                for meta in self._results:
                    if meta[u'src_compression_type'] is not None:
                        src_compression_type = meta[u'src_compression_type'][
                            u'name']
                    else:
                        src_compression_type = u'NONE'

                    if meta[u'dst_compression_type'] is not None:
                        dst_compression_type = meta[u'dst_compression_type'][
                            u'name']
                    else:
                        dst_compression_type = u'NONE'

                    if u'error_details' in meta:
                        error_details = meta[u'error_details']
                    else:
                        error_details = u''

                    src_file_size = meta[u'src_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else TO_UNICODE(meta[u'src_file_size'])

                    dst_file_size = meta[u'dst_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else TO_UNICODE(meta[u'dst_file_size'])

                    rowset.append([
                        meta[u'name'],
                        meta[u'dst_file_name'],
                        src_file_size,
                        dst_file_size,
                        src_compression_type,
                        dst_compression_type,
                        meta[u'result_status'],
                        error_details
                    ])
            return {
                u'rowtype': [
                    RESULT_TEXT_COLUMN_DESC(u'source'),
                    RESULT_TEXT_COLUMN_DESC(u'target'),
                    RESULT_FIXED_COLUMN_DESC(u'source_size'),
                    RESULT_FIXED_COLUMN_DESC(u'target_size'),
                    RESULT_TEXT_COLUMN_DESC(u'source_compression'),
                    RESULT_TEXT_COLUMN_DESC(u'target_compression'),
                    RESULT_TEXT_COLUMN_DESC(u'status'),
                    RESULT_TEXT_COLUMN_DESC(u'message'),
                ],
                u'rowset': sorted(rowset),
            }
        else:  # DOWNLOAD
            if hasattr(self, u'_results'):
                for meta in self._results:
                    dst_file_size = meta[u'dst_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else TO_UNICODE(meta[u'dst_file_size'])

                    if u'error_details' in meta:
                        error_details = meta[u'error_details']
                    else:
                        error_details = u''
                    rowset.append([
                        meta[u'dst_file_name'],
                        dst_file_size,
                        meta[u'result_status'],
                        error_details
                    ])
            return {
                u'rowtype': [
                    RESULT_TEXT_COLUMN_DESC(u'file'),
                    RESULT_FIXED_COLUMN_DESC(u'size'),
                    RESULT_TEXT_COLUMN_DESC(u'status'),
                    RESULT_TEXT_COLUMN_DESC(u'message'),
                ],
                u'rowset': sorted(rowset),
            }

    def _expand_filenames(self, locations):
        canonical_locations = []
        for file_name in locations:
            if self._command_type == CMD_TYPE_UPLOAD:
                file_name = os.path.expanduser(file_name)
                if not os.path.isabs(file_name):
                    file_name = os.path.join(GET_CWD(), file_name)
                files = glob.glob(file_name)
                canonical_locations += files
            else:
                canonical_locations.append(file_name)

        return canonical_locations

    def _init_encryption_material(self):
        self._encryption_material = []

        if u'data' in self._ret and \
                        u'encryptionMaterial' in self._ret[u'data'] and \
                        self._ret[u'data'][u'encryptionMaterial'] is not None:
            root_node = self._ret[u'data'][u'encryptionMaterial']
            self.logger.debug(self._command_type)
            self.logger.debug(u'root_node=%s', root_node)

            if self._command_type == CMD_TYPE_UPLOAD:
                self._encryption_material.append(
                    SnowflakeS3FileEncryptionMaterial(
                        query_stage_master_key=root_node[
                            u'queryStageMasterKey'],
                        query_id=root_node[u'queryId'],
                        smk_id=root_node[u'smkId']))
            else:
                for elem in root_node:
                    if elem is not None:
                        self._encryption_material.append(
                            SnowflakeS3FileEncryptionMaterial(
                                query_stage_master_key=elem[
                                    u'queryStageMasterKey'],
                                query_id=elem[u'queryId'],
                                smk_id=elem[u'smkId']))

    def _parse_command(self):
        if u'data' in self._ret:
            self._command_type = self._ret[u'data'][u'command']
        else:
            self._command_type = u'Unknown'

        self._init_encryption_material()
        if u'data' in self._ret and \
                        u'src_locations' in self._ret[u'data'] and \
                isinstance(self._ret[u'data'][u'src_locations'], list):
            self._src_locations = self._ret[u'data'][u'src_locations']
        else:
            Error.errorhandler_wrapper(
                self._cursor.connection, self._cursor,
                DatabaseError,
                {
                    u'msg': u'Failed to parse the location',
                    u'errno': ER_INVALID_STAGE_LOCATION
                }
            )

        if self._command_type == CMD_TYPE_UPLOAD:
            self._src_files = self._expand_filenames(self._src_locations)
            self._auto_compress = \
                u'autoCompress' not in self._ret[u'data'] or \
                self._ret[u'data'][u'autoCompress']
            self._source_compression = self._ret[u'data'][
                u'sourceCompression'].lower() \
                if u'sourceCompression' in self._ret[u'data'] else u''
        else:
            self._src_files = set(self._src_locations)
            self._src_file_to_encryption_material = {}
            if len(self._ret[u'data'][u'src_locations']) == len(
                    self._encryption_material):
                for idx, src_location in enumerate(self._src_locations):
                    self.logger.debug(src_location)
                    self.logger.debug(self._encryption_material[idx])
                    self._src_file_to_encryption_material[src_location] = \
                        self._encryption_material[idx]
            elif len(self._encryption_material) != 0:
                # some encryption material exists. Zero means no encryption
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    InternalError,
                    {
                        u'msg': (
                            u"The number of downloading files doesn't match "
                            u"the encryption materials: "
                            u"files={files}, encmat={encmat}").format(
                            files=len(self._ret[u'data'][u'src_locations']),
                            encmat=len(self._encryption_material)),
                        u'errno':
                            ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL
                    })

            self._local_location = os.path.expanduser(
                self._ret[u'data'][u'localLocation'])
            if not os.path.isdir(self._local_location):
                # NOTE: isdir follows the symlink
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        u'msg':
                            u'The local path is not a directory: {0}'.format(
                                self._local_location),
                        u'errno': ER_LOCAL_PATH_NOT_DIRECTORY
                    })

        self._parallel = self._ret[u'data'][u'parallel']
        self._overwrite = u'overwrite' in self._ret[u'data'] and \
                          self._ret[u'data'][u'overwrite']
        self._stage_location_type = self._ret[u'data'][u'stageInfo'][
            u'locationType'].upper()
        self._stage_location = self._ret[u'data'][u'stageInfo'][u'location']
        self._stage_credentials = self._ret[u'data'][u'stageInfo'][u'creds']
        self._stage_credentials['region'] = self._ret[u'data'][u'stageInfo'][
            u'region']
        if self._stage_location_type not in (S3_FS, LOCAL_FS):
            Error.errorhandler_wrapper(
                self._cursor.connection, self._cursor,
                OperationalError,
                {
                    u'msg': (u'Destination location type is not valid: '
                             u'{stage_location_type}').format(
                        stage_location_type=self._stage_location_type,
                    ),
                    u'errno': ER_INVALID_STAGE_FS
                })

    def _init_file_metadata(self):
        self.logger.info(u"command type: %s", self._command_type)
        self._file_metadata = {}
        if self._command_type == CMD_TYPE_UPLOAD:
            if len(self._src_files) == 0:
                file_name = self._ret[u'data'][u'src_locations'] \
                    if u'data' in self._ret and u'src_locations' in \
                                                self._ret[u'data'] else u'None'
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        u'msg': u"File doesn't exist: {file}".format(
                            file=file_name),
                        u'errno': ER_FILE_NOT_EXISTS
                    })
            for file_name in self._src_files:
                if not os.path.exists(file_name):
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            u'msg': u"File doesn't exist: {file}".format(
                                file=file_name),
                            u'errno': ER_FILE_NOT_EXISTS
                        })
                elif os.path.isdir(file_name):
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            u'msg': (u"Not a file but "
                                     u"a directory: {file}").format(
                                file=file_name),
                            u'errno': ER_FILE_NOT_EXISTS
                        })
                statinfo = os.stat(file_name)
                self._file_metadata[file_name] = {
                    u'name': os.path.basename(file_name),
                    u'src_file_name': file_name,
                    u'src_file_size': statinfo.st_size,
                    u'stage_location': os.path.expanduser(
                        self._stage_location),
                    u'stage_location_type': self._stage_location_type,
                    u'stage_credentials': self._stage_credentials,
                }
                if len(self._encryption_material) > 0:
                    self._file_metadata[file_name][u'encryption_material'] = \
                        self._encryption_material[0]
        elif self._command_type == CMD_TYPE_DOWNLOAD:
            for file_name in self._src_files:
                if len(file_name) > 0:
                    self.logger.debug(file_name)
                    first_path_sep = file_name.find(u'/')
                    dst_file_name = file_name[first_path_sep + 1:] \
                        if first_path_sep >= 0 else file_name
                    self._file_metadata[file_name] = {
                        u'name': os.path.basename(file_name),
                        u'src_file_name': file_name,
                        u'dst_file_name': dst_file_name,
                        u'stage_location': os.path.expanduser(
                            self._stage_location),
                        u'stage_location_type': self._stage_location_type,
                        u'stage_credentials': self._stage_credentials,
                        u'local_location': self._local_location,
                    }
                    if file_name in self._src_file_to_encryption_material:
                        self._file_metadata[file_name][
                            u'encryption_material'] = \
                            self._src_file_to_encryption_material[file_name]

    def _process_file_compression_type(self):
        user_specified_source_compression = None
        if self._source_compression == u'auto_detect':
            auto_detect = True
        elif self._source_compression == u'none':
            auto_detect = False
        else:
            user_specified_source_compression = \
                FileCompressionType.lookupByMimeSubType(
                    self._source_compression)
            if user_specified_source_compression is None or not \
                    user_specified_source_compression[u'is_supported']:
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        u'msg': (u'Feature is not supported: '
                                 u'{0}').format(
                            user_specified_source_compression
                        ),
                        u'errno': ER_COMPRESSION_NOT_SUPPORTED
                    })

            auto_detect = False

        for file_name in self._src_files:
            meta = self._file_metadata[file_name]

            current_file_compression_type = None
            if auto_detect:
                mimetypes.init()
                mime_type_str, encoding = mimetypes.guess_type(file_name)

                if encoding is None:
                    test = None
                    with open(file_name, 'rb') as f:
                        test = f.read(4)
                    if file_name.endswith('.br'):
                        encoding = 'br'
                    elif test and test[:3] == b'ORC':
                        mime_type_str = 'snowflake/orc'
                        encoding = 'orc'
                    elif test and test == b'PAR1':
                        mime_type_str = 'snowflake/parquet'
                        encoding = 'parquet'
                    elif test and (int(binascii.hexlify(test), 16) == 0x28B52FFD):
                        encoding = 'zstd'

                if encoding is not None:
                    self.logger.info(u'detected the encoding %s: file=%s',
                                     encoding, file_name)
                    current_file_compression_type = \
                        FileCompressionType.lookupByMimeSubType(encoding)
                else:
                    self.logger.info(u'no file encoding was detected: file=%s',
                                     file_name)

                if current_file_compression_type is not None and not \
                        current_file_compression_type[u'is_supported']:
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            u'msg': (u'Feature is not supported: '
                                     u'{0}').format(
                                current_file_compression_type
                            ),
                            u'errno': ER_COMPRESSION_NOT_SUPPORTED
                        })
            else:
                current_file_compression_type = \
                    user_specified_source_compression

            if current_file_compression_type is not None:
                meta[u'src_compression_type'] = current_file_compression_type
                if current_file_compression_type[u'is_supported']:
                    meta[u'dst_compression_type'] = \
                        current_file_compression_type
                    meta[u'require_compress'] = False
                    meta[u'dst_file_name'] = meta[u'name']
                else:
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            u'msg': (u'Feature is not supported: '
                                     u'{0}').format(
                                current_file_compression_type
                            ), u'errno': ER_COMPRESSION_NOT_SUPPORTED
                        })
            else:
                # src is not compressed but the destination want to be
                # compressed unless the users disable it
                meta[u'require_compress'] = self._auto_compress
                meta[u'src_compression_type'] = None
                if self._auto_compress:
                    meta[u'dst_file_name'] = \
                        meta[u'name'] + \
                        FileCompressionType.Types[u'GZIP'][u'file_extension']
                    meta[u'dst_compression_type'] = \
                        FileCompressionType.Types[u'GZIP']
                else:
                    meta[u'dst_file_name'] = meta[u'name']
                    meta[u'dst_compression_type'] = None

            self._file_metadata[file_name] = meta

    @staticmethod
    def greatest_common_prefix(s1, s2):
        if s1 is None or s2 is None:
            return None
        min_len = min(len(s1), len(s2))
        ret = []
        for idx in range(min_len):
            if s1[idx] == s2[idx]:
                ret.append(s1[idx])
            else:
                break
        return u''.join(ret)

    def _filter_existing_files(self):
        dst_file_name_to_src_file_name = {}

        for file_name, meta in self._file_metadata.items():
            if meta[u'dst_file_name'] in dst_file_name_to_src_file_name:
                prev_src_file = dst_file_name_to_src_file_name[
                    meta[u'dst_file_name']]
            else:
                prev_src_file = None
            dst_file_name_to_src_file_name[meta[u'dst_file_name']] = file_name
            if prev_src_file is not None:
                meta[u'result_status'] = RESULT_STATUS_COLLISION
                meta[
                    u'error_details'] = \
                    u'{prev} has the same name as {cur}'.format(
                        prev=prev_src_file,
                        cur=file_name)
            else:
                self.logger.debug(u"No dst file name found for %s",
                                  prev_src_file)

        if len(dst_file_name_to_src_file_name) == 0:
            return

        logger = getLogger(__name__)
        logger.info(u'dst files: %s', dst_file_name_to_src_file_name)
        # determine the greatest common prefix for all stage file names so that
        # we can call s3 API to list the objects and get thier digest to
        # compare with local files
        if self._command_type == CMD_TYPE_UPLOAD:
            stage_file_names = dst_file_name_to_src_file_name.keys()
        else:
            stage_file_names = dst_file_name_to_src_file_name.values()

        stage_file_names = sorted(stage_file_names)
        self.logger.debug(stage_file_names)

        file_prefix = SnowflakeFileTransferAgent.greatest_common_prefix(
            stage_file_names[0], stage_file_names[-1])
        self.logger.info(u'Greatest common prefix: %s', file_prefix)

        if self._stage_location_type == S3_FS:
            try:
                s3client = SnowflakeS3Util.create_s3_client(
                    self._stage_credentials,
                    use_accelerate_endpoint=self._use_accelerate_endpoint)
                self._existing_files = \
                    SnowflakeS3Util.filter_existing_files_s3(
                        s3client, self._stage_location,
                        file_prefix)
                self.logger.info(u"existing files: %s", self._existing_files)
            except Exception as err:
                import logging
                if self.logger.getEffectiveLevel() <= logging.DEBUG:
                    self.logger.exception('Failed to check the existing files')
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor, OperationalError,
                    {
                        u'msg': (u'Failed to check the existing '
                                 u'files: {0}').format(
                            err),
                        u'errno': ER_FAILED_TO_CHECK_EXISTING_FILES
                    }
                )
            s3location = SnowflakeS3Util.extract_bucket_name_and_path(
                self._stage_location
            )
            if self._command_type == CMD_TYPE_DOWNLOAD:
                for file_name, meta in self._file_metadata.items():
                    s3_full_path = s3location.s3path + file_name
                    if s3_full_path in self._existing_files:
                        meta[u'src_file_size'] = self._existing_files[
                            s3_full_path]
                    else:
                        meta[u'src_file_size'] = 1  # safeguard
