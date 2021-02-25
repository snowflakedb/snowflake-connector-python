#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import json
import os
from collections import namedtuple
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient, ContentSettings, ExponentialRetry

from .constants import HTTP_HEADER_VALUE_OCTET_STREAM, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

logger = getLogger(__name__)

"""
Azure Location: Azure container name + path
"""
AzureLocation = namedtuple(
    "AzureLocation", [
        "container_name",  # Azure container name
        "path"  # Azure path name

    ])


class SnowflakeAzureUtil(object):
    """Azure Utility class."""

    @staticmethod
    def create_client(stage_info: Dict[str, Any],
                      use_accelerate_endpoint: bool = False) -> BlobServiceClient:
        """Creates a client object with a stage credential.

        Args:
            stage_info: Information about the stage.
            use_accelerate_endpoint: Not used for Azure client.

        Returns:
            The client to communicate with GCS.
        """
        stage_credentials = stage_info['creds']
        sas_token = stage_credentials['AZURE_SAS_TOKEN']
        if sas_token and sas_token.startswith('?'):
            sas_token = sas_token[1:]
        end_point = stage_info['endPoint']
        if end_point.startswith('blob.'):
            end_point = end_point[len('blob.'):]
        client = BlobServiceClient(
            account_url=f"https://{stage_info['storageAccount']}.blob.{end_point}",
            credential=sas_token)
        client._config.retry_policy = ExponentialRetry(
            initial_backoff=1,
            increment_base=2,
            max_attempts=60,
            random_jitter_range=2
        )

        return client

    @staticmethod
    def extract_container_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        container_name = stage_location
        path = ''

        # split stage location as bucket name and path
        if '/' in stage_location:
            container_name = stage_location[0:stage_location.index('/')]
            path = stage_location[stage_location.index('/') + 1:]
            if path and not path.endswith('/'):
                path += '/'

        return AzureLocation(
            container_name=container_name,
            path=path)

    @staticmethod
    def get_file_header(meta: 'SnowflakeFileMeta', filename):
        """Gets Azure file properties."""
        client: BlobServiceClient = meta.client
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(meta.stage_info['location'])
        try:
            # HTTP HEAD request
            blob = client.get_blob_client(azure_location.container_name,
                                          azure_location.path + filename)
            blob_details = blob.get_blob_properties()
        except ResourceNotFoundError:
            meta.result_status = ResultStatus.NOT_FOUND_FILE
            return FileHeader(
                digest=None,
                content_length=None,
                encryption_metadata=None
            )
        except HttpResponseError as err:
            logger.debug(f"Caught exception's status code: {err.status_code} and message: {str(err)}")
            if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                logger.debug("AZURE Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
            else:
                logger.debug(f'Unexpected Azure error: {err} '
                             f'container: {azure_location.container_name}, path: {azure_location.path}')
                meta.result_status = ResultStatus.ERROR

            return
        meta.result_status = ResultStatus.UPLOADED
        encryptiondata = json.loads(blob_details.metadata.get('encryptiondata', 'null'))
        encryption_metadata = EncryptionMetadata(
            key=encryptiondata['WrappedContentKey']['EncryptedKey'],
            iv=encryptiondata['ContentEncryptionIV'],
            matdesc=blob_details.metadata['matdesc'],
        ) if encryptiondata else None

        return FileHeader(
            digest=blob_details.metadata.get('sfcdigest'),
            content_length=blob_details.size,
            encryption_metadata=encryption_metadata
        )

    @staticmethod
    def _detect_azure_token_expire_error(err):
        if err.status_code != 403:
            return False
        errstr = str(err)
        return "Signature not valid in the specified time frame" in errstr or \
               "Server failed to authenticate the request." in errstr

    @staticmethod
    def upload_file(data_file: str,
                    meta: 'SnowflakeFileMeta',
                    encryption_metadata: 'EncryptionMetadata',
                    max_concurrency: int,
                    multipart_threshold: int,
                    ):
        """Uploads the local file to Azure's Blob Storage.

        Args:
            data_file: File path on local system.
            meta: The File meta object (contains credentials and remote location).
            encryption_metadata: Encryption metadata to be set on object.
            max_concurrency: Not applicable to Azure.
            multipart_threshold: The number of bytes after which size a file should be uploaded concurrently in chunks.
                Not applicable to Azure.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None.
        """
        azure_metadata = {
            'sfcdigest': meta.sha256_digest,
        }
        if encryption_metadata:
            azure_metadata.update({
                'encryptiondata': json.dumps({
                    'EncryptionMode': 'FullBlob',
                    'WrappedContentKey': {
                        'KeyId': 'symmKey1',
                        'EncryptedKey': encryption_metadata.key,
                        'Algorithm': 'AES_CBC_256'
                    },
                    'EncryptionAgent': {
                        'Protocol': '1.0',
                        'EncryptionAlgorithm': 'AES_CBC_128',
                    },
                    'ContentEncryptionIV': encryption_metadata.iv,
                    'KeyWrappingMetadata': {
                        'EncryptionLibrary': 'Java 5.3.0'
                    }
                }),
                'matdesc': encryption_metadata.matdesc
            })
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(
            meta.stage_info['location'])
        path = azure_location.path + meta.dst_file_name.lstrip('/')

        client: BlobServiceClient = meta.client
        callback = None
        upload_src = None
        upload_size = None

        if meta.src_stream is None:
            upload_size = os.path.getsize(data_file)
            upload_src = open(data_file, 'rb')
        else:
            upload_src = meta.real_src_stream or meta.src_stream
            upload_size = upload_src.seek(0, os.SEEK_END)
            upload_src.seek(0)

        if meta.put_azure_callback:
            callback = meta.put_azure_callback(
                data_file,
                upload_size,
                output_stream=meta.put_callback_output_stream,
                show_progress_bar=meta.show_progress_bar)

        def azure_callback(response):
            current = response.context['upload_stream_current']
            total = response.context['data_stream_total']
            if current is not None:
                callback(current)
                logger.debug("data transfer progress from sdk callback. "
                             f"current: {current}, total: {total}")

        try:
            blob = client.get_blob_client(
                azure_location.container_name,
                path
            )
            blob.upload_blob(
                upload_src,
                metadata=azure_metadata,
                overwrite=True,
                max_concurrency=max_concurrency,
                raw_response_hook=azure_callback if meta.put_azure_callback else None,
                content_settings=ContentSettings(
                    content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
                    content_encoding='utf-8',
                )
            )
        except HttpResponseError as err:
            logger.debug(f"Caught exception's status code: {err.status_code} and message: {err}")
            if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                logger.debug("AZURE Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
            else:
                meta.last_error = err
                meta.result_status = ResultStatus.NEED_RETRY
            return
        finally:
            if meta.src_stream is None:
                upload_src.close()

        logger.debug('DONE putting a file')
        meta.dst_file_size = meta.upload_size
        meta.result_status = ResultStatus.UPLOADED
        # Comparing with s3, azure haven't experienced OpenSSL.SSL.SysCallError,
        # so we will add logic to catch it only when it happens

    @staticmethod
    def _native_download_file(meta: 'SnowflakeFileMeta', full_dst_file_name, max_concurrency):
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(meta.stage_info['location'])
        path = azure_location.path + meta.src_file_name.lstrip('/')
        client: BlobServiceClient = meta.client

        callback = None
        if meta.get_azure_callback:
            callback = meta.get_azure_callback(
                meta.src_file_name,
                meta.src_file_size,
                output_stream=meta.get_callback_output_stream,
                show_progress_bar=meta.show_progress_bar)

        def azure_callback(response):
            current = response.context['download_stream_current']
            total = response.context['data_stream_total']
            if current is not None:
                callback(current)
                logger.debug(f"data transfer progress from sdk callback. current: {current}, total: {total}")
        try:
            blob = client.get_blob_client(
                azure_location.container_name,
                path
            )
            with open(full_dst_file_name, 'wb') as download_f:
                download = blob.download_blob(
                    max_concurrency=max_concurrency,
                    raw_response_hook=azure_callback if meta.put_azure_callback else None,
                )
                download.readinto(download_f)

        except HttpResponseError as err:
            logger.debug(f"Caught exception's status code: {err.status_code} and message: {str(err)}")
            if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                logger.debug("AZURE Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
            else:
                meta.last_error = err
                meta.result_status = ResultStatus.NEED_RETRY
            return
        meta.result_status = ResultStatus.DOWNLOADED
