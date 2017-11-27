
from __future__ import division

import os
from collections import namedtuple
from logging import getLogger
import json
from azure.storage.blob import BlockBlobService
from azure.common import (AzureMissingResourceHttpError, AzureHttpError)
from azure.storage.blob.models import ContentSettings
from .constants import (SHA256_DIGEST, ResultStatus, FileHeader)
from .encryption_util import (EncryptionMetadata)


"""
Azure Location: Azure container name + path
"""
AzureLocation = namedtuple(
    "AzureLocation", [
        "container_name",  # Azure container name
        "path"  # Azure path name

    ])


class SnowflakeAzureUtil(object):
    """
    Azure Utility class
    """

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False):
        """
        Creates a client object with a stage credential
        :param stage_credentials: a stage credential
        :param use_accelerate_endpoint: is accelerate endpoint?
        :return: client
        """
        stage_credentials = stage_info[u'creds']
        sas_token = stage_credentials[u'AZURE_SAS_TOKEN']
        if sas_token and sas_token.startswith(u'?'):
            sas_token = sas_token[1:]
        client = BlockBlobService(account_name=stage_info[u'storageAccount'], sas_token=sas_token)
        return client

    @staticmethod
    def extract_container_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        container_name = stage_location
        path = u''

        # split stage location as bucket name and path
        if u'/' in stage_location:
            container_name = stage_location[0:stage_location.index(u'/')]
            path = stage_location[stage_location.index(u'/') + 1:]
            if path and not path.endswith(u'/'):
                path += u'/'

        return AzureLocation(
            container_name=container_name,
            path=path)

    @staticmethod
    def get_file_header(meta, filename):
        """
        Gets Azure file properties
        :param meta: file meta object
        :return:  FileHeader if no error,
        u'result_status'] for status.
        """

        logger = getLogger(__name__)
        client = meta[u'client']
        azure_location = SnowflakeAzureUtil.extract_container_name_and_path(meta[u'stage_info'][u'location'])
        try:
            # HTTP HEAD request
            blob = client.get_blob_properties(azure_location.container_name, azure_location.path + filename)
        except AzureMissingResourceHttpError:
            meta[u'result_status'] = ResultStatus.NOT_FOUND_FILE
            return FileHeader(
                digest=None,
                content_length=None,
                encryption_metadata=None
            )
        except AzureHttpError as err:
            if(err.status_code == 403 and "Signature not valid in the specified time frame" in err.message):
                logger.debug(u"AZURE Token expired. Renew and retry")
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return None
            else:
                logger.debug(u'Unexpected Azure error: %s'
                             u'container: %s, path: %s',
                             err, azure_location.container_name, azure_location.path)
                meta[u'result_status'] = ResultStatus.ERROR
                return None

        meta[u'result_status'] = ResultStatus.UPLOADED
        encryptiondata = json.loads(blob.metadata.get(u'encryptiondata', u'null'))

        encryption_metadata = EncryptionMetadata(
            key=encryptiondata[u'WrappedContentKey'][u'EncryptedKey'],
            iv=encryptiondata[u'ContentEncryptionIV'],
            matdesc=blob.metadata[u'matdesc'],
        ) if encryptiondata else None

        return FileHeader(
            digest=blob.metadata.get(u'sfcdigest'),
            content_length=blob.properties.content_length,
            encryption_metadata=encryption_metadata
        )

    @staticmethod
    def upload_file(data_file, meta, encryption_metadata, max_concurrency):
        logger = getLogger(__name__)
        try:
            azure_metadata = {
                u'sfcdigest': meta[SHA256_DIGEST],
            }
            if (encryption_metadata):
                azure_metadata.update({
                    u'encryptiondata': json.dumps({
                        u'EncryptionMode': u'FullBlob',
                        u'WrappedContentKey': {
                            u'KeyId': u'symmKey1',
                            u'EncryptedKey': encryption_metadata.key,
                            u'Algorithm': u'AES_CBC_256'
                        },
                        u'EncryptionAgent': {
                            u'Protocol': '1.0',
                            u'EncryptionAlgorithm': u'AES_CBC_128',
                        },
                        u'ContentEncryptionIV': encryption_metadata.iv,
                        u'KeyWrappingMetadata': {
                            u'EncryptionLibrary': u'Java 5.3.0'
                        }
                    }),
                    u'matdesc': encryption_metadata.matdesc
                })
            azure_location = SnowflakeAzureUtil.extract_container_name_and_path(
                meta[u'stage_info'][u'location'])
            path = azure_location.path + meta[u'dst_file_name'].lstrip('/')

            client = meta[u'client']
            callback = meta[u'put_callback'](
                    data_file,
                    os.path.getsize(data_file),
                    output_stream=meta[u'put_callback_output_stream']) if \
                    meta[u'put_callback'] else None

            def azure_callback(current, total):
                callback(current)
            client.create_blob_from_path(
                azure_location.container_name,
                path,
                data_file,
                progress_callback=azure_callback if
                    meta[u'put_callback'] else None,
                metadata=azure_metadata,
                max_connections=max_concurrency,
                content_settings=ContentSettings(
                    content_type=u'application/octet-stream',
                    content_encoding=u'utf-8',
                )
            )

            logger.debug(u'DONE putting a file')
            meta[u'dst_file_size'] = meta[u'upload_size']
            meta[u'result_status'] = ResultStatus.UPLOADED
        except AzureHttpError as err:
            if (err.status_code == 403 and "Signature not valid in the specified time frame" in err.message):
                logger.debug(u"AZURE Token expired. Renew and retry")
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return None
            else:
                meta[u'last_error'] = err
                meta[u'result_status'] = ResultStatus.NEED_RETRY
        # Comparing with s3, azure haven't experienced OpenSSL.SSL.SysCallError, so we will add logic to catch it only when it happens

    @staticmethod
    def _native_download_file(meta, full_dst_file_name, max_concurrency):
        logger = getLogger(__name__)
        try:
            azure_location = SnowflakeAzureUtil.extract_container_name_and_path(
                meta[u'stage_info'][u'location'])
            path = azure_location.path + meta[u'src_file_name'].lstrip('/')
            client = meta[u'client']

            callback = meta[u'get_callback'](
                meta[u'src_file_name'],
                meta[u'src_file_size'],
                output_stream=meta[u'get_callback_output_stream']) if \
                meta[u'get_callback'] else None

            def azure_callback(current, total):
                callback(current)
            client.get_blob_to_path(
                azure_location.container_name,
                path,
                full_dst_file_name,
                progress_callback=azure_callback if
                    meta[u'get_callback'] else None,
                max_connections=max_concurrency
            )

            meta[u'result_status'] = ResultStatus.DOWNLOADED
        except AzureHttpError as err:
            if (err.status_code == 403 and "Signature not valid in the specified time frame" in err.message):
                logger.debug(u"AZURE Token expired. Renew and retry")
                meta[u'result_status'] = ResultStatus.RENEW_TOKEN
                return None
            else:
                meta[u'last_error'] = err
                meta[u'result_status'] = ResultStatus.NEED_RETRY
        # Comparing with s3, azure haven't experienced OpenSSL.SSL.SysCallError, so we will add logic to catch it only when it happens
