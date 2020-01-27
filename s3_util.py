from __future__ import division

import logging
import os
from collections import namedtuple
from logging import getLogger

import boto3
import botocore.exceptions
import OpenSSL
from boto3.exceptions import RetriesExceededError, S3UploadFailedError
from boto3.s3.transfer import TransferConfig
from botocore.client import Config

from .compat import TO_UNICODE
from .constants import HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_VALUE_OCTET_STREAM, SHA256_DIGEST, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

SFC_DIGEST = u'sfc-digest'

AMZ_MATDESC = u"x-amz-matdesc"
AMZ_KEY = u"x-amz-key"
AMZ_IV = u"x-amz-iv"
ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

EXPIRED_TOKEN = u'ExpiredToken'
ADDRESSING_STYLE = u'virtual'  # explicit force to use virtual addressing style

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", [
        "bucket_name",  # S3 bucket name
        "s3path"  # S3 path name

    ])


class SnowflakeS3Util:
    """
    S3 Utility class
    """
    # magic number, given from  error message.
    DATA_SIZE_THRESHOLD = 67108864

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False):
        """
        Creates a client object with a stage credential
        :param stage_credentials: a stage credential
        :param use_accelerate_endpoint: is accelerate endpoint?
        :return: client
        """
        logger = getLogger(__name__)
        stage_credentials = stage_info[u'creds']
        security_token = stage_credentials.get(u'AWS_TOKEN', None)
        end_point = stage_info['endPoint']
        logger.debug(u"AWS_KEY_ID: %s", stage_credentials[u'AWS_KEY_ID'])

        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        end_point = (u'https://' + stage_info['endPoint']) if stage_info['endPoint'] else None

        config = Config(
            signature_version=u's3v4',
            s3={
                'use_accelerate_endpoint': use_accelerate_endpoint,
                'addressing_style': ADDRESSING_STYLE
            })
        client = boto3.resource(
            u's3',
            region_name=stage_info['region'],
            aws_access_key_id=stage_credentials[u'AWS_KEY_ID'],
            aws_secret_access_key=stage_credentials[u'AWS_SECRET_KEY'],
            aws_session_token=security_token,
            endpoint_url=end_point,
            config=config,
        )
        return client

    @staticmethod
    def extract_bucket_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        bucket_name = stage_location
        s3path = u''

        # split stage location as bucket name and path
        if u'/' in stage_location:
            bucket_name = stage_location[0:stage_location.index(u'/')]
            s3path = stage_location[stage_location.index(u'/') + 1:]
            if s3path and not s3path.endswith(u'/'):
                s3path += u'/'

        return S3Location(
            bucket_name=bucket_name,
            s3path=s3path)

    @staticmethod
    def _get_s3_object(meta, filename):
        logger = getLogger(__name__)
        client = meta[u'client']
        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            meta[u'stage_info'][u'location'])
        s3path = s3location.s3path + filename.lstrip('/')

        if logger.getEffectiveLevel() == logging.DEBUG:
            tmp_meta = {}
            for k, v in meta.items():
                if k != 'stage_credentials':
                    tmp_meta[k] = v
            logger.debug(
                u"s3location.bucket_name: %s, "
                u"s3location.s3path: %s, "
                u"s3fullpath: %s, "
                u'meta: %s',
                s3location.bucket_name,
                s3location.s3path,
                s3path, tmp_meta)
        return client.Object(s3location.bucket_name, s3path)

    @staticmethod
    def get_file_header(meta, filename):
        """
        Gets S3 file object
        :param meta: file meta object
        :return: S3 object if no error, otherwise None. Check meta[
        u'result_status'] for status.
        """

        logger = getLogger(__name__)
        akey = SnowflakeS3Util._get_s3_object(meta, filename)
        try:
            # HTTP HEAD request
            akey.load()
        except botocore.exceptions.ClientError as e:
            if e.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                logger.debug(u"AWS Token expired. Renew and retry")
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return None
            elif e.response[u'Error'][u'Code'] == u'404':
                logger.debug(u'not found. bucket: %s, path: %s',
                             akey.bucket_name, akey.key)
                meta[u'result_status'] = ResultStatus.NOT_FOUND_FILE
                return FileHeader(
                    digest=None,
                    content_length=None,
                    encryption_metadata=None,
                )
            elif e.response[u'Error'][u'Code'] == u'400':
                logger.debug(u'Bad request, token needs to be renewed: %s. '
                             u'bucket: %s, path: %s',
                             e.response[u'Error'][u'Message'],
                             akey.bucket_name, akey.key)
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return None
            logger.debug(
                u"Failed to get metadata for %s, %s: %s",
                akey.bucket_name, akey.key, e)
            meta[u'result_status'] = ResultStatus.ERROR
            return None

        meta[u'result_status'] = ResultStatus.UPLOADED
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
    def upload_file(data_file, meta, encryption_metadata, max_concurrency):
        logger = getLogger(__name__)
        try:
            s3_metadata = {
                HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM,
                SFC_DIGEST: meta[SHA256_DIGEST],
            }
            if (encryption_metadata):
                s3_metadata.update({
                    AMZ_IV: encryption_metadata.iv,
                    AMZ_KEY: encryption_metadata.key,
                    AMZ_MATDESC: encryption_metadata.matdesc,
                })
            s3location = SnowflakeS3Util.extract_bucket_name_and_path(
                meta[u'stage_info'][u'location'])
            s3path = s3location.s3path + meta[u'dst_file_name'].lstrip('/')

            akey = meta[u'client'].Object(s3location.bucket_name, s3path)
            akey.upload_file(
                data_file,
                Callback=meta[u'put_callback'](
                    data_file,
                    os.path.getsize(data_file),
                    output_stream=meta[u'put_callback_output_stream'],
                    show_progress_bar=meta[u'show_progress_bar']) if
                meta[u'put_callback'] else None,
                ExtraArgs={
                    u'Metadata': s3_metadata,
                },
                Config=TransferConfig(
                    multipart_threshold=SnowflakeS3Util.DATA_SIZE_THRESHOLD,
                    max_concurrency=max_concurrency,
                    num_download_attempts=10,
                )
            )

            logger.debug(u'DONE putting a file')
            meta[u'dst_file_size'] = meta[u'upload_size']
            meta[u'result_status'] = ResultStatus.UPLOADED
        except botocore.exceptions.ClientError as err:
            if err.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                logger.debug(u"AWS Token expired. Renew and retry")
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return
            logger.debug(
                u"Failed to upload a file: %s, err: %s",
                data_file, err, exc_info=True)
            raise err
        except S3UploadFailedError as err:
            if EXPIRED_TOKEN in TO_UNICODE(err):
                # Since AWS token expiration error can be encapsulated in
                # S3UploadFailedError, the text match is required to
                # identify the case.
                logger.debug(
                    'Failed to upload a file: %s, err: %s. Renewing '
                    'AWS Token and Retrying',
                    data_file, err)
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return

            meta[u'last_error'] = err
            meta[u'result_status'] = ResultStatus.NEED_RETRY
        except OpenSSL.SSL.SysCallError as err:
            meta[u'last_error'] = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it
                meta[
                    u'result_status'] = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta[u'result_status'] = ResultStatus.NEED_RETRY

    @staticmethod
    def _native_download_file(meta, full_dst_file_name, max_concurrency):
        logger = getLogger(__name__)
        try:
            akey = SnowflakeS3Util._get_s3_object(meta, meta[u'src_file_name'])
            akey.download_file(
                full_dst_file_name,
                Callback=meta[u'get_callback'](
                    meta[u'src_file_name'],
                    meta[u'src_file_size'],
                    output_stream=meta[u'get_callback_output_stream'],
                    show_progress_bar=meta[u'show_progress_bar']) if
                meta[u'get_callback'] else None,
                Config=TransferConfig(
                    multipart_threshold=SnowflakeS3Util.DATA_SIZE_THRESHOLD,
                    max_concurrency=max_concurrency,
                    num_download_attempts=10,
                )
            )
            meta[u'result_status'] = ResultStatus.DOWNLOADED
        except botocore.exceptions.ClientError as err:
            if err.response[u'Error'][u'Code'] == EXPIRED_TOKEN:
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
            else:
                logger.debug(
                    u"Failed to download a file: %s, err: %s",
                    full_dst_file_name, err, exc_info=True)
                raise err
        except RetriesExceededError as err:
            meta[u'result_status'] = ResultStatus.NEED_RETRY
            meta[u'last_error'] = err
        except OpenSSL.SSL.SysCallError as err:
            meta[u'last_error'] = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it

                meta[
                    u'result_status'] = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta[u'result_status'] = ResultStatus.NEED_RETRY
