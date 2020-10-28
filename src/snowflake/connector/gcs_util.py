#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import json
import os
from logging import getLogger

import requests

from .constants import HTTP_HEADER_CONTENT_ENCODING, SHA256_DIGEST, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

GCS_METADATA_PREFIX = 'x-goog-meta-'
GCS_METADATA_SFC_DIGEST = GCS_METADATA_PREFIX + 'sfc-digest'
GCS_METADATA_MATDESC_KEY = GCS_METADATA_PREFIX + 'matdesc'
GCS_METADATA_ENCRYPTIONDATAPROP = GCS_METADATA_PREFIX + 'encryptiondata'
GCS_FILE_HEADER_DIGEST = 'gcs-file-header-digest'
GCS_FILE_HEADER_CONTENT_LENGTH = 'gcs-file-header-content-length'
GCS_FILE_HEADER_ENCRYPTION_METADATA = 'gcs-file-header-encryption-metadata'
CONTENT_CHUNK_SIZE = 10 * 1024


class SnowflakeGCSUtil:
    """GCS Utility class."""

    @staticmethod
    def create_client(stage_info,
                      use_accelerate_endpoint: bool = False):
        """Creates a client object with given stage credentials.

        Args:
            stage_info: Access credentials and info of a stage.
            use_accelerate_endpoint: Whether to use an accelerated endpoint? This is not applicable to GCS.

        Returns:
            The client to communicate with GCS.
        """
        logger = getLogger(__name__)
        stage_credentials = stage_info['creds']
        security_token = stage_credentials.get('GCS_ACCESS_TOKEN')

        if security_token:
            logger.debug("len(GCS_ACCESS_TOKEN): %s", len(security_token))
            logger.debug("GCS operations with an access token are currently "
                         "unsupported")
            client = None

        else:
            logger.debug("No access token received from GS, constructing "
                         "anonymous client")
            client = None

        return client

    @staticmethod
    def upload_file(data_file, meta, encryption_metadata, max_concurrency):
        """Uploads the local file to remote storage.

        Args:
            data_file: File path on local system.
            meta: The File meta object (contains credentials and remote location).
            encryption_metadata: Encryption metadata to be set on object.
            max_concurrency: Not applicable to GCS.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None, if uploading was successful.
        """
        logger = getLogger(__name__)

        if meta.get('presigned_url', None):
            # Use presigned url to upload the object

            content_encoding = ""
            if meta.get('dst_compression_type') is not None:
                content_encoding = meta['dst_compression_type']['name'].lower()

            # We set the contentEncoding to blank for GZIP files. We don't
            # want GCS to think our gzip files are gzips because it makes
            # them download uncompressed, and none of the other providers do
            # that. There's essentially no way for us to prevent that
            # behavior. Bad Google.
            if content_encoding and content_encoding == 'gzip':
                content_encoding = ""

            gcs_headers = {
                HTTP_HEADER_CONTENT_ENCODING: content_encoding,
                GCS_METADATA_SFC_DIGEST: meta[SHA256_DIGEST],
            }

            if encryption_metadata:
                gcs_headers.update({
                    GCS_METADATA_ENCRYPTIONDATAPROP: json.dumps({
                        'EncryptionMode': 'FullBlob',
                        'WrappedContentKey': {
                            'KeyId': 'symmKey1',
                            'EncryptedKey': encryption_metadata.key,
                            'Algorithm': 'AES_CBC_256'
                        },
                        'EncryptionAgent': {
                            'Protocol': '1.0',
                            'EncryptionAlgorithm': 'AES_CBC_256',
                        },
                        'ContentEncryptionIV': encryption_metadata.iv,
                        'KeyWrappingMetadata': {
                            'EncryptionLibrary': 'Java 5.3.0'
                        }
                    }),
                    GCS_METADATA_MATDESC_KEY: encryption_metadata.matdesc
                })

            with open(data_file, 'rb') as fd:
                try:
                    response = requests.put(
                        meta['presigned_url'],
                        data=fd,
                        headers=gcs_headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as errh:
                    logger.debug("GCS file upload Http Error: %s", errh)
                    # Presigned urls can be generated for any xml-api operation
                    # offered by GCS. Hence the error codes expected are similar
                    # to xml api.
                    # https://cloud.google.com/storage/docs/xml-api/reference-status

                    # According to the above resource, GCS recommends retrying
                    # for the following error codes.
                    if errh.response.status_code in [403, 408, 429, 500, 503]:
                        meta['last_error'] = errh
                        meta['result_status'] = ResultStatus.NEED_RETRY
                        return
                    elif (errh.response.status_code == 400 and
                          ('last_error' not in meta or meta['last_error'].response.status_code != 400)):
                        # Only attempt to renew urls if this isn't the second time this happens
                        meta['last_error'] = errh
                        meta['result_status'] = ResultStatus.RENEW_PRESIGNED_URL
                        return
                    # raise anything else
                    raise errh
                except requests.exceptions.Timeout as errt:
                    logger.debug("GCS file upload Timeout Error: %s", errt)
                    meta['last_error'] = errt
                    meta['result_status'] = ResultStatus.NEED_RETRY
                    return

            if meta['put_callback']:
                meta['put_callback'](
                    data_file,
                    meta['src_file_size'],
                    output_stream=meta['put_callback_output_stream'],
                    show_progress_bar=meta['show_progress_bar'])(
                    meta['src_file_size'])

            logger.debug('DONE putting a file')
            meta['dst_file_size'] = meta['upload_size']
            meta['result_status'] = ResultStatus.UPLOADED

            meta[GCS_FILE_HEADER_DIGEST] = gcs_headers[GCS_METADATA_SFC_DIGEST]
            meta[GCS_FILE_HEADER_CONTENT_LENGTH] = meta['upload_size']
            meta[GCS_FILE_HEADER_ENCRYPTION_METADATA] = \
                gcs_headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None)
        else:
            # Use the storage client to upload the object
            # Currently not supported, given that we can't obtain
            # location-scoped access tokens
            logger.error("GCS upload operation with an access token is "
                         "currently unsupported")
            meta['result_status'] = ResultStatus.ERROR

    @staticmethod
    def _native_download_file(meta, full_dst_file_name, max_concurrency):
        """Downloads the remote object to local file.

        Args:
            meta: File meta object (contains credentials and remote location).
            full_dst_file_name: Local path of the file to download to.
            max_concurrency: Not applicable to GCS.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None, if downloading was successful.
        """
        logger = getLogger(__name__)

        if meta.get('presigned_url', None):
            # Use presigned url to download the object
            try:
                response = requests.get(meta['presigned_url'], stream=True)
                response.raise_for_status()

                with open(full_dst_file_name, 'wb') as fd:
                    for chunk in response.raw.stream(CONTENT_CHUNK_SIZE,
                                                     decode_content=False):
                        fd.write(chunk)
            except requests.exceptions.HTTPError as errh:
                logger.debug("GCS file download Http Error: %s", errh)
                # Presigned urls can be generated for any xml-api operation
                # offered by GCS. Hence the error codes expected are similar
                # to xml api.
                # https://cloud.google.com/storage/docs/xml-api/reference-status

                # According to the above resource, GCS recommends retrying
                # for the following error codes.
                if errh.response.status_code in [403, 408, 429, 500, 503]:
                    meta['last_error'] = errh
                    meta['result_status'] = ResultStatus.NEED_RETRY
                    return
                elif (errh.response.status_code == 400 and
                      ('last_error' not in meta or meta['last_error'].errh.response.status_code != 400)):
                    # Only attempt to renew urls if this isn't the second time this happens
                    meta['last_error'] = errh
                    meta['result_status'] = ResultStatus.RENEW_PRESIGNED_URL
                    return
                # raise anything else
                raise errh
            except requests.exceptions.Timeout as errt:
                logger.debug("GCS file download Timeout Error: %s", errt)
                meta['last_error'] = errt
                meta['result_status'] = ResultStatus.NEED_RETRY
                return

            encryption_metadata = None

            if response.headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None):
                encryptiondata = json.loads(
                    response.headers[GCS_METADATA_ENCRYPTIONDATAPROP])

                if encryptiondata:
                    encryption_metadata = EncryptionMetadata(
                        key=encryptiondata['WrappedContentKey']['EncryptedKey'],
                        iv=encryptiondata['ContentEncryptionIV'],
                        matdesc=response.headers[GCS_METADATA_MATDESC_KEY]
                        if GCS_METADATA_MATDESC_KEY in response.headers
                        else None,
                    )

            # Sadly, we can only determine the src file size after we've
            # downloaded it, unlike the other cloud providers where the
            # metadata can be read beforehand.
            meta['src_file_size'] = os.path.getsize(full_dst_file_name)

            if meta['get_callback']:
                meta['get_callback'](
                    meta['src_file_name'],
                    meta['src_file_size'],
                    output_stream=meta['get_callback_output_stream'],
                    show_progress_bar=meta['show_progress_bar'])(
                    meta['src_file_size'])

            logger.debug('DONE getting a file')
            meta['result_status'] = ResultStatus.DOWNLOADED

            meta[GCS_FILE_HEADER_DIGEST] = response.headers.get(
                GCS_METADATA_SFC_DIGEST, None)
            meta[GCS_FILE_HEADER_CONTENT_LENGTH] = len(response.content)
            meta[GCS_FILE_HEADER_ENCRYPTION_METADATA] = encryption_metadata
        else:
            # Use the storage client to download the object
            # Currently not supported, given that we can't obtain
            # location-scoped access tokens
            logger.error("GCS download operation with an access token is "
                         "currently unsupported")
            meta['result_status'] = ResultStatus.ERROR

    @staticmethod
    def get_file_header(meta, filename):
        """Gets the remote file's metadata.

        Args:
            meta: Remote file's metadata info.
            filename: Not applicable to GCS.

        Returns:
            The file header, with expected properties populated or None, based on how the request goes with the
            storage provider.

        Notes:
            Sometimes this method is called to verify that the file has indeed been uploaded. In cases of presigned
            url, we have no way of verifying that, except with the http status code of 200 which we have already
            confirmed and set the meta['result_status'] = UPLOADED/DOWNLOADED.
        """
        if meta.get('presigned_url', None):
            if meta.get('result_status', None) == ResultStatus.UPLOADED \
                    or meta.get('result_status', None) == ResultStatus.DOWNLOADED:
                return FileHeader(
                    digest=meta.get(
                        GCS_FILE_HEADER_DIGEST, None),
                    content_length=meta.get(
                        GCS_FILE_HEADER_CONTENT_LENGTH, None),
                    encryption_metadata=meta.get(
                        GCS_FILE_HEADER_ENCRYPTION_METADATA, None),
                )
            else:
                meta['result_status'] = ResultStatus.NOT_FOUND_FILE

        return FileHeader(
            digest=None,
            content_length=None,
            encryption_metadata=None
        )
