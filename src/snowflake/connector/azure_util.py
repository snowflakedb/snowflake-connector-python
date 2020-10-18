#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import json
import os
from collections import namedtuple
from logging import getLogger

from .constants import HTTP_HEADER_VALUE_OCTET_STREAM, SHA256_DIGEST, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

use_new_azure_api = False

try:
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    from azure.storage.blob import BlobServiceClient, ContentSettings, ExponentialRetry
    use_new_azure_api = True
except ImportError:
    import logging
    import requests
    from azure.common import AzureHttpError, AzureMissingResourceHttpError
    from azure.storage.blob import BlockBlobService
    from azure.storage.blob.models import ContentSettings
    from azure.storage.common._http.httpclient import HTTPResponse, _HTTPClient
    from azure.storage.common._serialization import _get_data_bytes_or_stream_only
    from azure.storage.common.retry import ExponentialRetry

    class RawBodyReadingClient(_HTTPClient):
        """Class that allows Azure to download files with content-encoding=gzip compressed.

        For more information see: https://github.com/Azure/azure-storage-python/issues/509. This client overrides the
        default HTTP client and downloads uncompressed. This workaround was provided by Microsoft.
        """

        def perform_request(self, request):
            """Sends an HTTPRequest to Azure Storage and returns an HTTPResponse.

            If the response code indicates an error, raise an HTTPError.
            """
            # Verify whether the body is in bytes or either a file-like/stream object
            if request.body:
                request.body = _get_data_bytes_or_stream_only('request.body', request.body)

            # Construct the URI
            uri = self.protocol.lower() + '://' + request.host + request.path

            # Send the request
            response = self.session.request(request.method,
                                            uri,
                                            params=request.query,
                                            headers=request.headers,
                                            data=request.body or None,
                                            timeout=self.timeout,
                                            proxies=self.proxies,
                                            stream=True)

            # Parse the response
            status = int(response.status_code)
            response_headers = {}
            for key, name in response.headers.items():
                # Preserve the case of metadata
                if key.lower().startswith('x-ms-meta-'):
                    response_headers[key] = name
                else:
                    response_headers[key.lower()] = name

            wrap = HTTPResponse(status, response.reason, response_headers, response.raw.read())
            response.close()

            return wrap

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

    # max_connections works over this size
    DATA_SIZE_THRESHOLD = 67108864

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint: bool = False):
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
        if use_new_azure_api:
            client = BlobServiceClient(
                account_url="https://{}.blob.{}".format(
                    stage_info['storageAccount'],
                    end_point
                ),
                credential=sas_token)
            client._config.retry_policy = ExponentialRetry(
                initial_backoff=1,
                increment_base=2,
                max_attempts=60,
                random_jitter_range=2
            )
        else:
            client = BlockBlobService(account_name=stage_info['storageAccount'],
                                      sas_token=sas_token,
                                      endpoint_suffix=end_point)
            client._httpclient = RawBodyReadingClient(session=requests.session(), protocol="https", timeout=2000)
            client.retry = ExponentialRetry(
                initial_backoff=1, increment_base=2, max_attempts=60, random_jitter_range=2).retry

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
    def get_file_header(meta, filename):
        """Gets Azure file properties."""
        client = meta['client']
        azure_logger = None
        backup_logging_level = None
        if not use_new_azure_api:
            azure_logger = logging.getLogger('azure.storage.common.storageclient')
            backup_logging_level = azure_logger.level
            # Critical (50) is the highest level, so we need to set it to something higher to silence logging message
            azure_logger.setLevel(60)
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(
            meta['stage_info']['location'])
        if use_new_azure_api:
            try:
                # HTTP HEAD request
                blob = client.get_blob_client(azure_location.container_name,
                                              azure_location.path + filename)
                blob_details = blob.get_blob_properties()
            except ResourceNotFoundError:
                meta['result_status'] = ResultStatus.NOT_FOUND_FILE
                return FileHeader(
                    digest=None,
                    content_length=None,
                    encryption_metadata=None
                )
            except HttpResponseError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    logger.debug('Unexpected Azure error: %s'
                                 'container: %s, path: %s',
                                 err, azure_location.container_name,
                                 azure_location.path)
                    meta['result_status'] = ResultStatus.ERROR
                return
        else:
            try:
                # HTTP HEAD request
                blob = client.get_blob_properties(azure_location.container_name,
                                                  azure_location.path + filename)
            except AzureMissingResourceHttpError:
                meta['result_status'] = ResultStatus.NOT_FOUND_FILE
                return FileHeader(
                    digest=None,
                    content_length=None,
                    encryption_metadata=None
                )
            except AzureHttpError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    logger.debug('Unexpected Azure error: %s'
                                 'container: %s, path: %s',
                                 err, azure_location.container_name,
                                 azure_location.path)
                    meta['result_status'] = ResultStatus.ERROR
                return
            finally:
                azure_logger.setLevel(backup_logging_level)
        meta['result_status'] = ResultStatus.UPLOADED
        if use_new_azure_api:
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
        else:
            encryptiondata = json.loads(blob.metadata.get('encryptiondata', 'null'))
            encryption_metadata = EncryptionMetadata(
                key=encryptiondata['WrappedContentKey']['EncryptedKey'],
                iv=encryptiondata['ContentEncryptionIV'],
                matdesc=blob.metadata['matdesc'],
            ) if encryptiondata else None

            return FileHeader(
                digest=blob.metadata.get('sfcdigest'),
                content_length=blob.properties.content_length,
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
    def upload_file(data_file, meta, encryption_metadata, max_concurrency):
        azure_metadata = {
            'sfcdigest': meta[SHA256_DIGEST],
        }
        if (encryption_metadata):
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
            meta['stage_info']['location'])
        path = azure_location.path + meta['dst_file_name'].lstrip('/')

        client = meta['client']
        callback = None
        if meta['put_azure_callback']:
            callback = meta['put_azure_callback'](
                data_file,
                os.path.getsize(data_file),
                output_stream=meta['put_callback_output_stream'],
                show_progress_bar=meta['show_progress_bar'])

        if use_new_azure_api:
            def azure_callback(response):
                current = response.context['upload_stream_current']
                total = response.context['data_stream_total']
                if current is not None:
                    callback(current)
                    logger.debug("data transfer progress from sdk callback. "
                                 "current: %s, total: %s",
                                 current, total)

            try:
                blob = client.get_blob_client(
                    azure_location.container_name,
                    path
                )
                with open(data_file, 'rb') as upload_f:
                    blob.upload_blob(
                        upload_f,
                        metadata=azure_metadata,
                        overwrite=True,
                        max_concurrency=max_concurrency,
                        raw_response_hook=azure_callback if meta['put_azure_callback'] else None,
                        content_settings=ContentSettings(
                            content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
                            content_encoding='utf-8',
                        )
                    )
            except HttpResponseError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    meta['last_error'] = err
                    meta['result_status'] = ResultStatus.NEED_RETRY
                return
        else:
            def azure_callback(current, total):
                callback(current)
                logger.debug("data transfer progress from sdk callback. "
                             "current: %s, total: %s",
                             current, total)

            try:
                client.create_blob_from_path(
                    azure_location.container_name,
                    path,
                    data_file,
                    progress_callback=azure_callback if
                    meta['put_azure_callback'] else None,
                    metadata=azure_metadata,
                    max_connections=max_concurrency,
                    content_settings=ContentSettings(
                        content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
                        content_encoding='utf-8'
                    )
                )
            except AzureHttpError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    meta['last_error'] = err
                    meta['result_status'] = ResultStatus.NEED_RETRY
                return

        logger.debug('DONE putting a file')
        meta['dst_file_size'] = meta['upload_size']
        meta['result_status'] = ResultStatus.UPLOADED
        # Comparing with s3, azure haven't experienced OpenSSL.SSL.SysCallError,
        # so we will add logic to catch it only when it happens

    @staticmethod
    def _native_download_file(meta, full_dst_file_name, max_concurrency):
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(
            meta['stage_info']['location'])
        path = azure_location.path + meta['src_file_name'].lstrip('/')
        client = meta['client']

        callback = None
        if meta['get_azure_callback']:
            callback = meta['get_azure_callback'](
                meta['src_file_name'],
                meta['src_file_size'],
                output_stream=meta['get_callback_output_stream'],
                show_progress_bar=meta['show_progress_bar'])

        if use_new_azure_api:
            def azure_callback(response):
                current = response.context['download_stream_current']
                total = response.context['data_stream_total']
                if current is not None:
                    callback(current)
                    logger.debug("data transfer progress from sdk callback. "
                                 "current: %s, total: %s",
                                 current, total)
            try:
                blob = client.get_blob_client(
                    azure_location.container_name,
                    path
                )
                with open(full_dst_file_name, 'wb') as download_f:
                    download = blob.download_blob(
                        max_concurrency=max_concurrency,
                        raw_response_hook=azure_callback if meta['put_azure_callback'] else None,
                    )
                    download.readinto(download_f)

            except HttpResponseError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    meta['last_error'] = err
                    meta['result_status'] = ResultStatus.NEED_RETRY
                return
        else:
            def azure_callback(current, total):
                callback(current)
                logger.debug("data transfer progress from sdk callback. "
                             "current: %s, total: %s",
                             current, total)
            try:
                client.get_blob_to_path(
                    azure_location.container_name,
                    path,
                    full_dst_file_name,
                    progress_callback=azure_callback if
                    meta['get_azure_callback'] else None,
                    max_connections=max_concurrency
                )
            except AzureHttpError as err:
                logger.debug("Caught exception's status code: {status_code} and message: {ex_representation}".format(
                    status_code=err.status_code,
                    ex_representation=str(err)
                ))
                if err.status_code == 403 and SnowflakeAzureUtil._detect_azure_token_expire_error(err):
                    logger.debug("AZURE Token expired. Renew and retry")
                    meta['result_status'] = ResultStatus.RENEW_TOKEN
                else:
                    meta['last_error'] = err
                    meta['result_status'] = ResultStatus.NEED_RETRY
                return
        meta['result_status'] = ResultStatus.DOWNLOADED
