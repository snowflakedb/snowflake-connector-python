#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import logging
import os
from collections import namedtuple
from logging import getLogger
from typing import TYPE_CHECKING

import boto3
import botocore.exceptions
import OpenSSL
from boto3.exceptions import RetriesExceededError, S3UploadFailedError
from boto3.s3.transfer import TransferConfig
from boto3.session import Session
from botocore.client import Config

from .constants import HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_VALUE_OCTET_STREAM, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

logger = getLogger(__name__)

SFC_DIGEST = 'sfc-digest'

AMZ_MATDESC = "x-amz-matdesc"
AMZ_KEY = "x-amz-key"
AMZ_IV = "x-amz-iv"
ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

EXPIRED_TOKEN = 'ExpiredToken'
ADDRESSING_STYLE = 'virtual'  # explicit force to use virtual addressing style

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", [
        "bucket_name",  # S3 bucket name
        "s3path"  # S3 path name

    ])


class SnowflakeS3Util:
    """S3 Utility class."""

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False) -> Session.resource:
        """Creates a client object with a stage credential.

        Args:
            stage_info: Information about the stage.
            use_accelerate_endpoint: Whether or not to use accelerated endpoint (Default value = False).

        Returns:
            The client to communicate with S3.
        """
        stage_credentials = stage_info['creds']
        security_token = stage_credentials.get('AWS_TOKEN', None)

        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        end_point = ('https://' + stage_info['endPoint']) if stage_info['endPoint'] else None

        config = Config(
            signature_version='s3v4',
            s3={
                'use_accelerate_endpoint': use_accelerate_endpoint,
                'addressing_style': ADDRESSING_STYLE
            })
        client = boto3.resource(
            's3',
            region_name=stage_info['region'],
            aws_access_key_id=stage_credentials['AWS_KEY_ID'],
            aws_secret_access_key=stage_credentials['AWS_SECRET_KEY'],
            aws_session_token=security_token,
            endpoint_url=end_point,
            config=config,
        )
        return client

    @staticmethod
    def extract_bucket_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        bucket_name = stage_location
        s3path = ''

        # split stage location as bucket name and path
        if '/' in stage_location:
            bucket_name = stage_location[0:stage_location.index('/')]
            s3path = stage_location[stage_location.index('/') + 1:]
            if s3path and not s3path.endswith('/'):
                s3path += '/'

        return S3Location(
            bucket_name=bucket_name,
            s3path=s3path)

    @staticmethod
    def _get_s3_object(meta: 'SnowflakeFileMeta', filename):
        client = meta.client
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(meta.stage_info['location'])
        s3path = s3location.s3path + filename.lstrip('/')

        if logger.getEffectiveLevel() == logging.DEBUG:
            tmp_meta = {}
            log_black_list = ('stage_credentials', 'creds', 'encryption_material')
            for k, v in meta.__dict__.items():
                if k not in log_black_list:
                    tmp_meta[k] = v
            logger.debug(
                f"s3location.bucket_name: {s3location.bucket_name}, "
                f"s3location.s3path: {s3location.s3path}, "
                f"s3full_path: {s3path}, "
                f"meta: {tmp_meta}")
        return client.Object(s3location.bucket_name, s3path)

    @staticmethod
    def get_file_header(meta: 'SnowflakeFileMeta', filename):
        """Gets the remote file's metadata.

        Args:
            meta: Remote file's metadata info.
            filename: Name of remote file.

        Returns:
            The file header, with expected properties populated or None, based on how the request goes with the
            storage provider.
        """
        akey = SnowflakeS3Util._get_s3_object(meta, filename)
        try:
            # HTTP HEAD request
            akey.load()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == EXPIRED_TOKEN:
                logger.debug("AWS Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
                return None
            elif e.response['Error']['Code'] == '404':
                logger.debug(f'not found. bucket: {akey.bucket_name}, path: {akey.key}')
                meta.result_status = ResultStatus.NOT_FOUND_FILE
                return FileHeader(
                    digest=None,
                    content_length=None,
                    encryption_metadata=None,
                )
            elif e.response['Error']['Code'] == '400':
                logger.debug(f'Bad request, token needs to be renewed: {e.response["Error"]["Message"]}. '
                             f'bucket: {akey.bucket_name}, path: {akey.key}')
                meta.result_status = ResultStatus.RENEW_TOKEN
                return None
            logger.debug(f"Failed to get metadata for {akey.bucket_name}, {akey.key}: {e}")
            meta.result_status = ResultStatus.ERROR
            return None

        meta.result_status = ResultStatus.UPLOADED
        encryption_metadata = EncryptionMetadata(
            key=akey.metadata.get(AMZ_KEY),
            iv=akey.metadata.get(AMZ_IV),
            matdesc=akey.metadata.get(AMZ_MATDESC),
        ) if akey.metadata.get(AMZ_KEY) else None

        return FileHeader(
            digest=akey.metadata.get(SFC_DIGEST),
            content_length=akey.content_length,
            encryption_metadata=encryption_metadata
        )

    @staticmethod
    def upload_file(data_file: str,
                    meta: 'SnowflakeFileMeta',
                    encryption_metadata: 'EncryptionMetadata',
                    max_concurrency: int,
                    multipart_threshold: int,
                    ):
        """Uploads the local file to S3.

        Args:
            data_file: File path on local system.
            meta: The File meta object (contains credentials and remote location).
            encryption_metadata: Encryption metadata to be set on object.
            max_concurrency: The maximum number of threads to used to upload.
            multipart_threshold: The number of bytes after which size a file should be uploaded concurrently in chunks.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None.
        """
        try:
            s3_metadata = {
                HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM,
                SFC_DIGEST: meta.sha256_digest,
            }
            if encryption_metadata:
                s3_metadata.update({
                    AMZ_IV: encryption_metadata.iv,
                    AMZ_KEY: encryption_metadata.key,
                    AMZ_MATDESC: encryption_metadata.matdesc,
                })
            s3location = SnowflakeS3Util.extract_bucket_name_and_path(
                meta.stage_info['location'])
            s3path = s3location.s3path + meta.dst_file_name.lstrip('/')

            akey = meta.client.Object(s3location.bucket_name, s3path)
            extra_args = {'Metadata': s3_metadata}
            config = TransferConfig(
                multipart_threshold=multipart_threshold,
                max_concurrency=max_concurrency,
                num_download_attempts=10,
            )

            if meta.src_stream is None:
                akey.upload_file(
                    data_file,
                    Callback=meta.put_callback(
                        data_file,
                        os.path.getsize(data_file),
                        output_stream=meta.put_callback_output_stream,
                        show_progress_bar=meta.show_progress_bar) if meta.put_callback else None,
                    ExtraArgs=extra_args,
                    Config=config
                )
            else:
                upload_stream = meta.real_src_stream or meta.src_stream
                upload_size = upload_stream.seek(0, os.SEEK_END)
                upload_stream.seek(0)

                akey.upload_fileobj(
                    upload_stream,
                    Callback=meta.put_callback(
                        data_file,
                        upload_size,
                        output_stream=meta.put_callback_output_stream,
                        show_progress_bar=meta.show_progress_bar) if meta.put_callback else None,
                    ExtraArgs=extra_args,
                    Config=config,
                )

            logger.debug('DONE putting a file')
            meta.dst_file_size = meta.upload_size
            meta.result_status = ResultStatus.UPLOADED
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == EXPIRED_TOKEN:
                logger.debug("AWS Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
                return
            logger.debug(f"Failed to upload a file: {data_file}, err: {err}", exc_info=True)
            raise err
        except S3UploadFailedError as err:
            if EXPIRED_TOKEN in str(err):
                # Since AWS token expiration error can be encapsulated in
                # S3UploadFailedError, the text match is required to
                # identify the case.
                logger.debug(f'Failed to upload a file: {data_file}, err: {err}. Renewing AWS Token and Retrying')
                meta.result_status = ResultStatus.RENEW_TOKEN
                return

            meta.last_error = err
            meta.result_status = ResultStatus.NEED_RETRY
        except OpenSSL.SSL.SysCallError as err:
            meta.last_error = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it
                meta.result_status = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta.result_status = ResultStatus.NEED_RETRY

    @staticmethod
    def _native_download_file(meta: 'SnowflakeFileMeta', full_dst_file_name, max_concurrency):
        try:
            akey = SnowflakeS3Util._get_s3_object(meta, meta.src_file_name)
            akey.download_file(
                full_dst_file_name,
                Callback=meta.get_callback(
                    meta.src_file_name,
                    meta.src_file_size,
                    output_stream=meta.get_callback_output_stream,
                    show_progress_bar=meta.show_progress_bar) if
                meta.get_callback else None,
                Config=TransferConfig(
                    multipart_threshold=meta.multipart_threshold,
                    max_concurrency=max_concurrency,
                    num_download_attempts=10,
                )
            )
            meta.result_status = ResultStatus.DOWNLOADED
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == EXPIRED_TOKEN:
                meta.result_status = ResultStatus.RENEW_TOKEN
            else:
                logger.debug(f"Failed to download a file: {full_dst_file_name}, err: {err}", exc_info=True)
                raise err
        except RetriesExceededError as err:
            meta.result_status = ResultStatus.NEED_RETRY
            meta.last_error = err
        except OpenSSL.SSL.SysCallError as err:
            meta.last_error = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it

                meta.result_status = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta.result_status = ResultStatus.NEED_RETRY
