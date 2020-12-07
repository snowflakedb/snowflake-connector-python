#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import binascii
import glob
import mimetypes
import os
import shutil
import sys
import tempfile
import threading
from concurrent.futures.thread import ThreadPoolExecutor
from logging import getLogger
from time import sleep, time
from typing import IO, Optional, Union

import botocore.exceptions

from .azure_util import SnowflakeAzureUtil
from .compat import GET_CWD, IS_WINDOWS
from .constants import SHA256_DIGEST, ResultStatus
from .converter_snowsql import SnowflakeConverterSnowSQL
from .errorcode import (
    ER_COMPRESSION_NOT_SUPPORTED,
    ER_FAILED_TO_DOWNLOAD_FROM_STAGE,
    ER_FAILED_TO_UPLOAD_TO_STAGE,
    ER_FILE_NOT_EXISTS,
    ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL,
    ER_INVALID_STAGE_FS,
    ER_INVALID_STAGE_LOCATION,
    ER_LOCAL_PATH_NOT_DIRECTORY,
)
from .errors import DatabaseError, Error, InternalError, OperationalError, ProgrammingError
from .file_compression_type import FileCompressionType
from .file_util import SnowflakeFileUtil
from .gcs_util import SnowflakeGCSUtil
from .local_util import SnowflakeLocalUtil
from .remote_storage_util import SnowflakeFileEncryptionMaterial, SnowflakeRemoteStorageUtil
from .s3_util import SnowflakeS3Util

S3_FS = 'S3'
AZURE_FS = 'AZURE'
GCS_FS = 'GCS'
LOCAL_FS = 'LOCAL_FS'
CMD_TYPE_UPLOAD = 'UPLOAD'
CMD_TYPE_DOWNLOAD = 'DOWNLOAD'
FILE_PROTOCOL = 'file://'

RESULT_TEXT_COLUMN_DESC = lambda name: {
    'name': name, 'type': 'text',
    'length': 16777216, 'precision': None,
    'scale': None, 'nullable': False}
RESULT_FIXED_COLUMN_DESC = lambda name: {
    'name': name, 'type': 'fixed',
    'length': 5, 'precision': 0,
    'scale': 0,
    'nullable': False}

MB = 1024.0 * 1024.0

INJECT_WAIT_IN_PUT = 0

logger = getLogger(__name__)


def _update_progress(
        file_name: str, start_time: float, total_size: float, progress: Union[float, int],
        output_stream: Optional[IO] = sys.stdout, show_progress_bar: Optional[bool] = True) -> float:
    barLength = 10  # Modify this to change the length of the progress bar
    total_size /= MB
    status = ""
    elapsed_time = time() - start_time
    throughput = (total_size / elapsed_time) if elapsed_time != 0.0 else 0.0
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
            throughput=throughput)
    if not status and show_progress_bar:
        status = "({elapsed_time:.3f}s, {throughput:.2f}MB/s)".format(
            elapsed_time=elapsed_time,
            throughput=throughput)
    if status:
        block = int(round(barLength * progress))
        text = "\r{file_name}({size:.2f}MB): [{bar}] {percentage:.2f}% {status}".format(
            file_name=file_name,
            size=total_size,
            bar="#" * block + "-" * (barLength - block),
            percentage=progress * 100.0,
            status=status)
        output_stream.write(text)
        output_stream.flush()
    logger.debug('filename: %s, start_time: %s, total_size: %s, progress: %s, '
                 'show_progress_bar: %s',
                 file_name, start_time, total_size, progress, show_progress_bar)
    return progress == 1.0


class SnowflakeProgressPercentage():
    """Built-in Progress bar for PUT commands."""

    def __init__(
            self, filename: str, filesize: Union[int, float],
            output_stream: Optional[IO] = sys.stdout,
            show_progress_bar: Optional[bool] = True):
        last_pound_char = filename.rfind('#')
        if last_pound_char < 0:
            last_pound_char = len(filename)
        self._filename = os.path.basename(filename[0:last_pound_char])
        self._output_stream = output_stream
        self._show_progress_bar = show_progress_bar
        self._size = float(filesize)
        self._seen_so_far = 0
        self._done = False
        self._start_time = time()
        self._lock = threading.Lock()

    def __call__(self, bytes_amount: int):
        raise NotImplementedError


class SnowflakeS3ProgressPercentage(SnowflakeProgressPercentage):
    def __init__(
            self, filename: str, filesize: Union[int, float],
            output_stream: Optional[IO] = sys.stdout,
            show_progress_bar: Optional[bool] = True):
        super(SnowflakeS3ProgressPercentage, self).__init__(
            filename, filesize,
            output_stream=output_stream,
            show_progress_bar=show_progress_bar)

    def __call__(self, bytes_amount: int):
        # logger.debug("Bytes returned from callback %s", bytes_amount)
        with self._lock:
            if self._output_stream:
                self._seen_so_far += bytes_amount
                percentage = float(self._seen_so_far / self._size)
                if not self._done:
                    self._done = _update_progress(
                        self._filename, self._start_time,
                        self._size, percentage,
                        output_stream=self._output_stream,
                        show_progress_bar=self._show_progress_bar)


class SnowflakeAzureProgressPercentage(SnowflakeProgressPercentage):
    def __init__(self, filename: str, filesize: Union[int, float],
            output_stream: Optional[IO] = sys.stdout,
            show_progress_bar: Optional[bool] = True):
        super(SnowflakeAzureProgressPercentage, self).__init__(
            filename, filesize,
            output_stream=output_stream,
            show_progress_bar=show_progress_bar)

    def __call__(self, current: int):
        with self._lock:
            if self._output_stream:
                self._seen_so_far = current
                percentage = float(self._seen_so_far / self._size)
                if not self._done:
                    self._done = _update_progress(
                        self._filename, self._start_time,
                        self._size, percentage,
                        output_stream=self._output_stream,
                        show_progress_bar=self._show_progress_bar)


class SnowflakeFileTransferAgent(object):
    """Snowflake File Transfer Agent."""

    def __init__(self, cursor, command, ret,
                 put_callback=None,
                 put_azure_callback=None,
                 put_callback_output_stream=sys.stdout,
                 get_callback=None,
                 get_azure_callback=None,
                 get_callback_output_stream=sys.stdout,
                 show_progress_bar=True,
                 raise_put_get_error=True,
                 force_put_overwrite=True):
        self._cursor = cursor
        self._command = command
        self._ret = ret
        self._put_callback = put_callback
        self._put_azure_callback = \
            put_azure_callback if put_azure_callback else put_callback
        self._put_callback_output_stream = put_callback_output_stream
        self._get_callback = get_callback
        self._get_azure_callback = \
            get_azure_callback if get_azure_callback else get_callback
        self._get_callback_output_stream = get_callback_output_stream
        self._use_accelerate_endpoint = False
        self._raise_put_get_error = raise_put_get_error
        self._show_progress_bar = show_progress_bar
        self._force_put_overwrite = force_put_overwrite

    def execute(self):
        self._parse_command()

        self._init_file_metadata()

        if self._command_type == CMD_TYPE_UPLOAD:
            self._process_file_compression_type()

        self._transfer_accelerate_config()

        if self._command_type == CMD_TYPE_DOWNLOAD:
            if not os.path.isdir(self._local_location):
                os.makedirs(self._local_location)

        if self._stage_location_type == LOCAL_FS:
            if not os.path.isdir(self._stage_info['location']):
                os.makedirs(self._stage_info['location'])

        self._update_file_metas_with_presigned_url()

        small_file_metas = []
        large_file_metas = []
        for meta in self._file_metadata:
            meta['overwrite'] = self._overwrite
            meta['self'] = self
            if self._stage_location_type != LOCAL_FS:
                meta['put_callback'] = self._put_callback
                meta['put_azure_callback'] = self._put_azure_callback
                meta['put_callback_output_stream'] = \
                    self._put_callback_output_stream
                meta['get_callback'] = self._get_callback
                meta['get_azure_callback'] = self._get_azure_callback
                meta['get_callback_output_stream'] = \
                    self._get_callback_output_stream
                meta['show_progress_bar'] = self._show_progress_bar

                # multichunk uploader threshold
                if self._stage_location_type == S3_FS:
                    size_threshold = SnowflakeS3Util.DATA_SIZE_THRESHOLD
                else:
                    size_threshold = SnowflakeAzureUtil.DATA_SIZE_THRESHOLD
                if meta.get('src_file_size', 1) > size_threshold:
                    meta['parallel'] = self._parallel
                    large_file_metas.append(meta)
                else:
                    meta['parallel'] = 1
                    small_file_metas.append(meta)
            else:
                meta['parallel'] = 1
                small_file_metas.append(meta)

        logger.debug('parallel=[%s]', self._parallel)
        self._results = []
        if self._command_type == CMD_TYPE_UPLOAD:
            self.upload(large_file_metas, small_file_metas)
        else:
            self.download(large_file_metas, small_file_metas)

        # turn enum to string, in order to have backward compatible interface
        for result in self._results:
            result['result_status'] = result['result_status'].value

    def upload(self, large_file_metas, small_file_metas):
        storage_client = SnowflakeFileTransferAgent.get_storage_client(
            self._stage_location_type)
        client = storage_client.create_client(
            self._stage_info,
            use_accelerate_endpoint=self._use_accelerate_endpoint
        )
        for meta in small_file_metas:
            meta['client'] = client
        for meta in large_file_metas:
            meta['client'] = client

        if len(small_file_metas) > 0:
            self._upload_files_in_parallel(small_file_metas)
        if len(large_file_metas) > 0:
            self._upload_files_in_sequential(large_file_metas)

    def _transfer_accelerate_config(self):
        if self._stage_location_type == S3_FS:
            client = SnowflakeRemoteStorageUtil.create_client(
                self._stage_info,
                use_accelerate_endpoint=False)
            s3location = SnowflakeS3Util.extract_bucket_name_and_path(
                self._stage_info['location']
            )
            try:
                ret = client.meta.client.get_bucket_accelerate_configuration(
                    Bucket=s3location.bucket_name)
                self._use_accelerate_endpoint = \
                    ret and 'Status' in ret and \
                    ret['Status'] == 'Enabled'
            except botocore.exceptions.ClientError as e:
                if e.response['Error'].get('Code', 'Unknown') == \
                        'AccessDenied':
                    logger.debug(e)
                else:
                    # unknown error
                    logger.debug(e, exc_info=True)

            logger.debug(
                'use_accelerate_endpoint: %s',
                self._use_accelerate_endpoint)

    def _upload_files_in_parallel(self, file_metas):
        """Uploads files in parallel.

        Args:
            file_metas: List of metadata for files to be uploaded.
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            end_of_idx = idx + self._parallel if \
                idx + self._parallel <= len_file_metas else \
                len_file_metas

            logger.debug(
                'uploading files idx: {}/{}'.format(idx + 1, end_of_idx))

            target_meta = file_metas[idx:end_of_idx]
            while True:
                pool = ThreadPoolExecutor(len(target_meta))
                results = list(pool.map(
                    SnowflakeFileTransferAgent.upload_one_file,
                    target_meta))
                pool.shutdown()

                # need renew AWS token?
                retry_meta = []
                for result_meta in results:
                    if result_meta['result_status'] in [
                        ResultStatus.RENEW_TOKEN,
                        ResultStatus.RENEW_PRESIGNED_URL
                    ]:
                        retry_meta.append(result_meta)
                    else:
                        self._results.append(result_meta)

                if len(retry_meta) == 0:
                    # no new AWS token is required
                    break
                if any([result_meta['result_status'] == ResultStatus.RENEW_TOKEN
                        for result_meta in results]):
                    client = self.renew_expired_client()
                    for result_meta in retry_meta:
                        result_meta['client'] = client
                    if end_of_idx < len_file_metas:
                        for idx0 in range(idx + self._parallel, len_file_metas):
                            file_metas[idx0]['client'] = client
                if any([result_meta['result_status'] == ResultStatus.RENEW_PRESIGNED_URL
                        for result_meta in results]):
                    self._update_file_metas_with_presigned_url()
                target_meta = retry_meta

            if end_of_idx == len_file_metas:
                break
            idx += self._parallel

    def _upload_files_in_sequential(self, file_metas):
        """Uploads files in sequential. Retry if the access token expires.

        Args:
            file_metas: List of metadata for files to be uploaded.
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            logger.debug(
                'uploading files idx: {}/{}'.format(idx + 1, len_file_metas))
            result = SnowflakeFileTransferAgent.upload_one_file(
                file_metas[idx])
            if result['result_status'] == ResultStatus.RENEW_TOKEN:
                client = self.renew_expired_client()
                for idx0 in range(idx, len_file_metas):
                    file_metas[idx0]['client'] = client
                continue
            elif result['result_status'] == ResultStatus.RENEW_PRESIGNED_URL:
                self._update_file_metas_with_presigned_url()
                continue
            self._results.append(result)
            idx += 1
            if INJECT_WAIT_IN_PUT > 0:
                logger.debug('LONGEVITY TEST: waiting for %s',
                             INJECT_WAIT_IN_PUT)
                sleep(INJECT_WAIT_IN_PUT)

    @staticmethod
    def get_storage_client(stage_location_type):
        if (stage_location_type == LOCAL_FS):
            return SnowflakeLocalUtil
        elif (stage_location_type in [S3_FS, AZURE_FS, GCS_FS]):
            return SnowflakeRemoteStorageUtil
        else:
            return None

    @staticmethod
    def upload_one_file(meta):
        """Uploads one file.

        Args:
            meta: Metadata for file to be uploaded.

        Returns:
            Metadata of uploaded file.
        """
        logger = getLogger(__name__)

        logger.debug("uploading file=%s", meta['src_file_name'])
        meta['real_src_file_name'] = meta['src_file_name']
        tmp_dir = tempfile.mkdtemp()
        meta['tmp_dir'] = tmp_dir
        try:
            if meta['require_compress']:
                logger.debug('compressing file=%s', meta['src_file_name'])
                meta['real_src_file_name'], upload_size = \
                    SnowflakeFileUtil.compress_file_with_gzip(
                        meta['src_file_name'], tmp_dir)
            logger.debug(
                'getting digest file=%s', meta['real_src_file_name'])
            sha256_digest, upload_size = \
                SnowflakeFileUtil.get_digest_and_size_for_file(
                    meta['real_src_file_name'])
            meta[SHA256_DIGEST] = sha256_digest
            meta['upload_size'] = upload_size
            logger.debug('really uploading data')
            storage_client = SnowflakeFileTransferAgent.get_storage_client(
                meta['stage_location_type'])
            storage_client.upload_one_file_with_retry(meta)
            logger.debug(
                'done: status=%s, file=%s, real file=%s',
                meta['result_status'],
                meta['src_file_name'],
                meta['real_src_file_name'])
        except Exception as e:
            logger.exception(
                'Failed to upload a file: file=%s, real file=%s',
                meta['src_file_name'],
                meta['real_src_file_name'])
            meta['dst_file_size'] = 0
            if 'result_status' not in meta:
                meta['result_status'] = ResultStatus.ERROR
            meta['error_details'] = str(e)
            meta['error_details'] += \
                ", file={}, real file={}".format(
                    meta.get('src_file_name'), meta.get('real_src_file_name'))
        finally:
            logger.debug('cleaning up tmp dir: %s', tmp_dir)
            shutil.rmtree(tmp_dir)
        return meta

    def download(self, large_file_metas, small_file_metas):
        storage_client = SnowflakeFileTransferAgent.get_storage_client(
            self._stage_location_type)
        client = storage_client.create_client(
            self._stage_info,
            use_accelerate_endpoint=self._use_accelerate_endpoint
        )
        for meta in small_file_metas:
            meta['client'] = client
        for meta in large_file_metas:
            meta['client'] = client

        if len(small_file_metas) > 0:
            self._download_files_in_parallel(small_file_metas)
        if len(large_file_metas) > 0:
            self._download_files_in_sequential(large_file_metas)

    def _download_files_in_parallel(self, file_metas):
        """Downloads files in parallel.

        Args:
            file_metas: List of metadata for files to be downloaded.
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            end_of_idx = idx + self._parallel if \
                idx + self._parallel <= len_file_metas else \
                len_file_metas

            logger.debug(
                'downloading files idx: {} to {}'.format(idx, end_of_idx))

            target_meta = file_metas[idx:end_of_idx]
            while True:
                pool = ThreadPoolExecutor(len(target_meta))
                results = list(pool.map(
                    SnowflakeFileTransferAgent.download_one_file,
                    target_meta))
                pool.shutdown()

                # need renew AWS token?
                retry_meta = []
                for result_meta in results:
                    if result_meta[
                        'result_status'] in [
                        ResultStatus.RENEW_TOKEN,
                        ResultStatus.RENEW_PRESIGNED_URL
                    ]:
                        retry_meta.append(result_meta)
                    else:
                        self._results.append(result_meta)

                if len(retry_meta) == 0:
                    # no new AWS token is required
                    break
                if any([result_meta['result_status'] == ResultStatus.RENEW_TOKEN
                        for result_meta in results]):
                    client = self.renew_expired_client()
                    for result_meta in retry_meta:
                        result_meta['client'] = client
                if any([result_meta['result_status'] == ResultStatus.RENEW_PRESIGNED_URL
                        for result_meta in results]):
                    self._update_file_metas_with_presigned_url()
                if end_of_idx < len_file_metas:
                    for idx0 in range(idx + self._parallel, len_file_metas):
                        file_metas[idx0]['client'] = client
                target_meta = retry_meta

            if end_of_idx == len_file_metas:
                break
            idx += self._parallel

    def _download_files_in_sequential(self, file_metas):
        """Downloads files in sequential. Retry if the access token expires.

        Args:
            file_metas: List of metadata for files to be downloaded.
        """
        idx = 0
        len_file_metas = len(file_metas)
        while idx < len_file_metas:
            result = SnowflakeFileTransferAgent.download_one_file(
                file_metas[idx])
            if result['result_status'] == ResultStatus.RENEW_TOKEN:
                client = self.renew_expired_client()
                for idx0 in range(idx, len_file_metas):
                    file_metas[idx0]['client'] = client
                continue
            elif result['result_status'] == ResultStatus.RENEW_PRESIGNED_URL:
                self._update_file_metas_with_presigned_url()
                continue
            self._results.append(result)
            idx += 1
            if INJECT_WAIT_IN_PUT > 0:
                logger.debug('LONGEVITY TEST: waiting for %s',
                             INJECT_WAIT_IN_PUT)
                sleep(INJECT_WAIT_IN_PUT)

    @staticmethod
    def download_one_file(meta):
        """Download a one file.

        Args:
            meta: Metadata for file to be downloaded.

        Returns:
            Metadata of downloaded file.
        """
        logger = getLogger(__name__)

        tmp_dir = tempfile.mkdtemp()
        meta['tmp_dir'] = tmp_dir
        try:
            storage_client = SnowflakeFileTransferAgent.get_storage_client(
                meta['stage_location_type'])
            storage_client.download_one_file(meta)
            logger.debug(
                'done: status=%s, file=%s',
                meta.get('result_status'),
                meta.get('dst_file_name'))
        except Exception as e:
            logger.exception('Failed to download a file: %s',
                             meta['dst_file_name'])
            meta['dst_file_size'] = -1
            if 'result_status' not in meta:
                meta['result_status'] = ResultStatus.ERROR
            meta['error_details'] = str(e)
            meta['error_details'] += \
                ', file={}'.format(meta.get('dst_file_name'))
        finally:
            logger.debug('cleaning up tmp dir: %s', tmp_dir)
            shutil.rmtree(tmp_dir)
        return meta

    def renew_expired_client(self):
        logger = getLogger(__name__)
        logger.debug('renewing expired aws token')
        ret = self._cursor._execute_helper(
            self._command)  # rerun the command to get the credential
        stage_info = ret['data']['stageInfo']
        storage_client = SnowflakeFileTransferAgent.get_storage_client(
            self._stage_location_type)
        return storage_client.create_client(
            stage_info,
            use_accelerate_endpoint=self._use_accelerate_endpoint)

    def _update_file_metas_with_presigned_url(self):
        """Updates the file metas with presigned urls if any.

        Currently only the file metas generated for PUT/GET on a GCP account need the presigned urls.
        """
        logger = getLogger(__name__)

        storage_client_class = SnowflakeFileTransferAgent.get_storage_client(
            self._stage_location_type)

        # presigned url only applies to remote storage
        if storage_client_class is not SnowflakeRemoteStorageUtil:
            return

        storage_util_class = SnowflakeRemoteStorageUtil.getForStorageType(
            self._stage_location_type)

        # presigned url only applies to GCS
        if storage_util_class in [SnowflakeGCSUtil]:
            if self._command_type == CMD_TYPE_UPLOAD:
                logger.debug('getting presigned urls for upload')

                # Rewrite the command such that a new PUT call is made for each file
                # represented by the regex (if present) separately. This is the only
                # way to get the presigned url for that file.
                file_path_to_be_replaced = self.get_local_file_path_from_put_command(
                    self._command)

                for meta in self._file_metadata:
                    # At this point the connector has already figured out and
                    # validated that the local file exists and has also decided
                    # upon the destination file name and the compression type.
                    # The only thing that's left to do is to get the presigned
                    # url for the destination file. If the command originally
                    # referred to a single file, then the presigned url got in
                    # that case is simply ignore, since the file name is not what
                    # we want.

                    # GS only looks at the file name at the end of local file
                    # path to figure out the remote object name. Hence the prefix
                    # for local path is not necessary in the reconstructed command.
                    file_path_to_replace_with = meta['dst_file_name']
                    command_with_single_file = self._command
                    command_with_single_file = command_with_single_file.replace(
                        file_path_to_be_replaced,
                        file_path_to_replace_with)

                    logger.debug('getting presigned url for %s',
                                 file_path_to_replace_with)

                    ret = self._cursor._execute_helper(command_with_single_file)

                    if ret.get('data', dict()).get('stageInfo', None):
                        meta['stage_info'] = ret['data']['stageInfo']
                        meta['presigned_url'] = meta['stage_info'].get(
                            'presignedUrl', None)
            elif self._command_type == CMD_TYPE_DOWNLOAD:
                logger.debug('updating download file metas with presigned urls')

                for idx, meta in enumerate(self._file_metadata):
                    meta['presigned_url'] = self._presigned_urls[idx] \
                        if len(self._presigned_urls) > idx else None

    def result(self):
        converter_class = self._cursor._connection.converter_class
        rowset = []
        if self._command_type == CMD_TYPE_UPLOAD:
            if hasattr(self, '_results'):
                for meta in self._results:
                    if meta['src_compression_type'] is not None:
                        src_compression_type = meta['src_compression_type'][
                            'name']
                    else:
                        src_compression_type = 'NONE'

                    if meta['dst_compression_type'] is not None:
                        dst_compression_type = meta['dst_compression_type'][
                            'name']
                    else:
                        dst_compression_type = 'NONE'

                    error_details = meta.get('error_details', '')

                    src_file_size = meta['src_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else str(meta['src_file_size'])

                    dst_file_size = meta['dst_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else str(meta['dst_file_size'])

                    logger.debug("raise_put_get_error: %s, %s, %s, %s, %s",
                                 self._raise_put_get_error,
                                 meta['result_status'],
                                 type(meta['result_status']),
                                 ResultStatus.ERROR,
                                 type(ResultStatus.ERROR))
                    if self._raise_put_get_error and error_details:
                        Error.errorhandler_wrapper(
                            self._cursor.connection, self._cursor,
                            OperationalError,
                            {
                                'msg': error_details,
                                'errno': ER_FAILED_TO_UPLOAD_TO_STAGE,
                            }
                        )
                    rowset.append([
                        meta['name'],
                        meta['dst_file_name'],
                        src_file_size,
                        dst_file_size,
                        src_compression_type,
                        dst_compression_type,
                        meta['result_status'],
                        error_details
                    ])
            return {
                'rowtype': [
                    RESULT_TEXT_COLUMN_DESC('source'),
                    RESULT_TEXT_COLUMN_DESC('target'),
                    RESULT_FIXED_COLUMN_DESC('source_size'),
                    RESULT_FIXED_COLUMN_DESC('target_size'),
                    RESULT_TEXT_COLUMN_DESC('source_compression'),
                    RESULT_TEXT_COLUMN_DESC('target_compression'),
                    RESULT_TEXT_COLUMN_DESC('status'),
                    RESULT_TEXT_COLUMN_DESC('message'),
                ],
                'rowset': sorted(rowset),
            }
        else:  # DOWNLOAD
            if hasattr(self, '_results'):
                for meta in self._results:
                    dst_file_size = meta['dst_file_size'] \
                        if converter_class != SnowflakeConverterSnowSQL \
                        else str(meta['dst_file_size'])

                    error_details = meta.get('error_details', '')

                    if self._raise_put_get_error and error_details:
                        Error.errorhandler_wrapper(
                            self._cursor.connection, self._cursor,
                            OperationalError,
                            {
                                'msg': error_details,
                                'errno': ER_FAILED_TO_DOWNLOAD_FROM_STAGE,
                            }
                        )

                    rowset.append([
                        meta['dst_file_name'],
                        dst_file_size,
                        meta['result_status'],
                        error_details
                    ])
            return {
                'rowtype': [
                    RESULT_TEXT_COLUMN_DESC('file'),
                    RESULT_FIXED_COLUMN_DESC('size'),
                    RESULT_TEXT_COLUMN_DESC('status'),
                    RESULT_TEXT_COLUMN_DESC('message'),
                ],
                'rowset': sorted(rowset),
            }

    def _expand_filenames(self, locations):
        canonical_locations = []
        for file_name in locations:
            if self._command_type == CMD_TYPE_UPLOAD:
                file_name = os.path.expanduser(file_name)
                if not os.path.isabs(file_name):
                    file_name = os.path.join(GET_CWD(), file_name)
                if IS_WINDOWS and len(file_name) > 2 \
                        and file_name[0] == '/' and file_name[2] == ':':
                    # Windows path: /C:/data/file1.txt where it starts with slash
                    # followed by a drive letter and colon.
                    file_name = file_name[1:]
                files = glob.glob(file_name)
                canonical_locations += files
            else:
                canonical_locations.append(file_name)

        return canonical_locations

    def _init_encryption_material(self):
        self._encryption_material = []

        if 'data' in self._ret and \
                'encryptionMaterial' in self._ret['data'] and \
                self._ret['data']['encryptionMaterial'] is not None:
            root_node = self._ret['data']['encryptionMaterial']
            logger.debug(self._command_type)

            if self._command_type == CMD_TYPE_UPLOAD:
                self._encryption_material.append(
                    SnowflakeFileEncryptionMaterial(
                        query_stage_master_key=root_node[
                            'queryStageMasterKey'],
                        query_id=root_node['queryId'],
                        smk_id=root_node['smkId']))
            else:
                for elem in root_node:
                    if elem is not None:
                        self._encryption_material.append(
                            SnowflakeFileEncryptionMaterial(
                                query_stage_master_key=elem[
                                    'queryStageMasterKey'],
                                query_id=elem['queryId'],
                                smk_id=elem['smkId']))

    def _parse_command(self):
        if 'data' in self._ret:
            self._command_type = self._ret['data']['command']
        else:
            self._command_type = 'Unknown'

        self._init_encryption_material()
        if 'data' in self._ret and \
                'src_locations' in self._ret['data'] and \
                isinstance(self._ret['data']['src_locations'], list):
            self._src_locations = self._ret['data']['src_locations']
        else:
            Error.errorhandler_wrapper(
                self._cursor.connection, self._cursor,
                DatabaseError,
                {
                    'msg': 'Failed to parse the location',
                    'errno': ER_INVALID_STAGE_LOCATION
                }
            )

        if self._command_type == CMD_TYPE_UPLOAD:
            self._src_files = list(self._expand_filenames(self._src_locations))
            self._auto_compress = 'autoCompress' not in self._ret['data'] or self._ret['data']['autoCompress']
            self._source_compression = self._ret['data']['sourceCompression'].lower() if 'sourceCompression' in \
                                                                                         self._ret['data'] else ''
        else:
            self._src_files = list(self._src_locations)
            self._src_file_to_encryption_material = {}
            if len(self._ret['data']['src_locations']) == len(
                    self._encryption_material):
                for idx, src_file in enumerate(self._src_files):
                    logger.debug(src_file)
                    self._src_file_to_encryption_material[src_file] = \
                        self._encryption_material[idx]
            elif len(self._encryption_material) != 0:
                # some encryption material exists. Zero means no encryption
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    InternalError,
                    {
                        'msg': (
                            "The number of downloading files doesn't match "
                            "the encryption materials: "
                            "files={files}, encmat={encmat}").format(
                            files=len(self._ret['data']['src_locations']),
                            encmat=len(self._encryption_material)),
                        'errno':
                            ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL
                    })

            self._local_location = os.path.expanduser(
                self._ret['data']['localLocation'])
            if not os.path.isdir(self._local_location):
                # NOTE: isdir follows the symlink
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        'msg':
                            'The local path is not a directory: {}'.format(
                                self._local_location),
                        'errno': ER_LOCAL_PATH_NOT_DIRECTORY
                    })

        self._parallel = self._ret['data'].get('parallel', 1)
        self._overwrite = self._force_put_overwrite or \
                          self._ret['data'].get('overwrite', False)
        self._stage_location_type = self._ret['data']['stageInfo'][
            'locationType'].upper()
        self._stage_location = self._ret['data']['stageInfo']['location']
        self._stage_info = self._ret['data']['stageInfo']
        self._presigned_urls = self._ret['data'].get('presignedUrls', None)

        if self.get_storage_client(self._stage_location_type) is None:
            Error.errorhandler_wrapper(
                self._cursor.connection, self._cursor,
                OperationalError,
                {
                    'msg': ('Destination location type is not valid: '
                             '{stage_location_type}').format(
                        stage_location_type=self._stage_location_type,
                    ),
                    'errno': ER_INVALID_STAGE_FS
                })

    def _init_file_metadata(self):
        logger.debug("command type: %s", self._command_type)

        # The list of self-sufficient file metas that are sent to
        # remote storage clients to get operated on.
        self._file_metadata = []

        if self._command_type == CMD_TYPE_UPLOAD:
            if len(self._src_files) == 0:
                file_name = self._ret['data']['src_locations'] \
                    if 'data' in self._ret and 'src_locations' in \
                       self._ret['data'] else 'None'
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        'msg': "File doesn't exist: {file}".format(
                            file=file_name),
                        'errno': ER_FILE_NOT_EXISTS
                    })
            for file_name in self._src_files:
                if not os.path.exists(file_name):
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            'msg': "File doesn't exist: {file}".format(
                                file=file_name),
                            'errno': ER_FILE_NOT_EXISTS
                        })
                elif os.path.isdir(file_name):
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            'msg': ("Not a file but "
                                     "a directory: {file}").format(
                                file=file_name),
                            'errno': ER_FILE_NOT_EXISTS
                        })
                statinfo = os.stat(file_name)
                self._file_metadata += [{
                    'name': os.path.basename(file_name),
                    'src_file_name': file_name,
                    'src_file_size': statinfo.st_size,
                    'stage_location_type': self._stage_location_type,
                    'stage_info': self._stage_info,
                }]
            if len(self._encryption_material) > 0:
                for meta in self._file_metadata:
                    meta['encryption_material'] = self._encryption_material[0]
        elif self._command_type == CMD_TYPE_DOWNLOAD:
            for file_name in self._src_files:
                if len(file_name) > 0:
                    logger.debug(file_name)
                    first_path_sep = file_name.find('/')
                    dst_file_name = file_name[first_path_sep + 1:] \
                        if first_path_sep >= 0 else file_name
                    self._file_metadata += [{
                        'name': os.path.basename(file_name),
                        'src_file_name': file_name,
                        'dst_file_name': dst_file_name,
                        'stage_location_type': self._stage_location_type,
                        'stage_info': self._stage_info,
                        'local_location': self._local_location,
                    }]
            for meta in self._file_metadata:
                file_name = meta['src_file_name']
                if file_name in self._src_file_to_encryption_material:
                    meta['encryption_material'] = \
                        self._src_file_to_encryption_material[file_name]

    def _process_file_compression_type(self):
        user_specified_source_compression = None
        if self._source_compression == 'auto_detect':
            auto_detect = True
        elif self._source_compression == 'none':
            auto_detect = False
        else:
            user_specified_source_compression = \
                FileCompressionType.lookupByMimeSubType(
                    self._source_compression)
            if user_specified_source_compression is None or not \
                    user_specified_source_compression['is_supported']:
                Error.errorhandler_wrapper(
                    self._cursor.connection, self._cursor,
                    ProgrammingError,
                    {
                        'msg': ('Feature is not supported: '
                                 '{0}').format(
                            user_specified_source_compression
                        ),
                        'errno': ER_COMPRESSION_NOT_SUPPORTED
                    })

            auto_detect = False

        for meta in self._file_metadata:
            file_name = meta['src_file_name']

            current_file_compression_type = None
            if auto_detect:
                mimetypes.init()
                _, encoding = mimetypes.guess_type(file_name)

                if encoding is None:
                    with open(file_name, 'rb') as f:
                        test = f.read(4)
                    if file_name.endswith('.br'):
                        encoding = 'br'
                    elif test and test[:3] == b'ORC':
                        encoding = 'orc'
                    elif test and test == b'PAR1':
                        encoding = 'parquet'
                    elif test and (
                            int(binascii.hexlify(test), 16) == 0x28B52FFD):
                        encoding = 'zstd'

                if encoding is not None:
                    logger.debug('detected the encoding %s: file=%s',
                                 encoding, file_name)
                    current_file_compression_type = \
                        FileCompressionType.lookupByMimeSubType(encoding)
                else:
                    logger.debug('no file encoding was detected: file=%s',
                                 file_name)

                if current_file_compression_type is not None and not \
                        current_file_compression_type['is_supported']:
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            'msg': ('Feature is not supported: '
                                     '{0}').format(
                                current_file_compression_type
                            ),
                            'errno': ER_COMPRESSION_NOT_SUPPORTED
                        })
            else:
                current_file_compression_type = \
                    user_specified_source_compression

            if current_file_compression_type is not None:
                meta['src_compression_type'] = current_file_compression_type
                if current_file_compression_type['is_supported']:
                    meta['dst_compression_type'] = \
                        current_file_compression_type
                    meta['require_compress'] = False
                    meta['dst_file_name'] = meta['name']
                else:
                    Error.errorhandler_wrapper(
                        self._cursor.connection, self._cursor,
                        ProgrammingError,
                        {
                            'msg': ('Feature is not supported: '
                                     '{0}').format(
                                current_file_compression_type
                            ), 'errno': ER_COMPRESSION_NOT_SUPPORTED
                        })
            else:
                # src is not compressed but the destination want to be
                # compressed unless the users disable it
                meta['require_compress'] = self._auto_compress
                meta['src_compression_type'] = None
                if self._auto_compress:
                    meta['dst_file_name'] = \
                        meta['name'] + \
                        FileCompressionType.Types['GZIP']['file_extension']
                    meta['dst_compression_type'] = \
                        FileCompressionType.Types['GZIP']
                else:
                    meta['dst_file_name'] = meta['name']
                    meta['dst_compression_type'] = None

    def get_local_file_path_from_put_command(self, command):
        """Get the local file path from PUT command (Logic adopted from JDBC, written by Polita).

        Args:
            command: Command to be parsed and get the local file path out of.

        Returns:
            The local file path.
        """
        if command is None or len(command) == 0 or FILE_PROTOCOL not in command:
            return None

        if not self._cursor.PUT_SQL_RE.match(command):
            return None

        file_path_begin_index = command.find(FILE_PROTOCOL)
        is_file_path_quoted = command[file_path_begin_index - 1] == "'"
        file_path_begin_index += len(FILE_PROTOCOL)

        file_path = ""
        file_path_end_index = 0

        if is_file_path_quoted:
            file_path_end_index = command.find("'", file_path_begin_index)

            if file_path_end_index > file_path_begin_index:
                file_path = command[file_path_begin_index:file_path_end_index]
        else:
            index_list = []
            for delimiter in [' ', '\n', ';']:
                index = command.find(delimiter, file_path_begin_index)
                if index != -1:
                    index_list += [index]

            file_path_end_index = min(index_list) if index_list else -1

            if file_path_end_index > file_path_begin_index:
                file_path = command[file_path_begin_index:file_path_end_index]
            elif file_path_end_index == -1:
                file_path = command[file_path_begin_index:]

        return file_path
