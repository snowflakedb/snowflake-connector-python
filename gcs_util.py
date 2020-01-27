#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import json
import os
from logging import getLogger

import requests

from .constants import HTTP_HEADER_CONTENT_ENCODING, SHA256_DIGEST, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata

GCS_METADATA_PREFIX = u'x-goog-meta-'
GCS_METADATA_SFC_DIGEST = GCS_METADATA_PREFIX + u'sfc-digest'
GCS_METADATA_MATDESC_KEY = GCS_METADATA_PREFIX + u'matdesc'
GCS_METADATA_ENCRYPTIONDATAPROP = GCS_METADATA_PREFIX + u'encryptiondata'
GCS_FILE_HEADER_DIGEST = u'gcs-file-header-digest'
GCS_FILE_HEADER_CONTENT_LENGTH = u'gcs-file-header-content-length'
GCS_FILE_HEADER_ENCRYPTION_METADATA = u'gcs-file-header-encryption-metadata'
CONTENT_CHUNK_SIZE = 10 * 1024


class SnowflakeGCSUtil:
    """
    GCS Utility class
    """

    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False):
        """
        Creates a client object with a stage credential
        :param stage_credentials: a stage credential
        :param use_accelerate_endpoint: is accelerate endpoint? (inapplicable to GCS)
        :return: client
        """
        logger = getLogger(__name__)
        stage_credentials = stage_info[u'creds']
        security_token = stage_credentials.get(u'GCS_ACCESS_TOKEN')

        if security_token:
            logger.debug(u"len(GCS_ACCESS_TOKEN): %s", len(security_token))
            logger.debug(u"GCS operations with an access token are currently "
                         u"unsupported")
            client = None

        else:
            logger.debug(u"No access token received from GS, constructing "
                         u"anonymous client")
            client = None

        return client

    @staticmethod
    def upload_file(data_file, meta, encryption_metadata, max_concurrency):
        """
        Uploads the local file to remote storage
        :param data_file: file path on local system
        :param meta: file meta object (contains credentials and remote location)
        :param encryption_metadata: encryption metadata to be set on object
        :param max_concurrency: (inapplicable to GCS)
        :return: None, if successful. Otherwise, throws Exception.
        """
        logger = getLogger(__name__)

        if meta.get(u'presigned_url', None):
            # Use presigned url to upload the object

            content_encoding = ""
            if meta.get(u'dst_compression_type') is not None:
                content_encoding = meta[u'dst_compression_type'][u'name'].lower()

            # We set the contentEncoding to blank for GZIP files. We don't
            # want GCS to think our gzip files are gzips because it makes
            # them download uncompressed, and none of the other providers do
            # that. There's essentially no way for us to prevent that
            # behavior. Bad Google.
            if content_encoding and content_encoding == u'gzip':
                content_encoding = ""

            gcs_headers = {
                HTTP_HEADER_CONTENT_ENCODING: content_encoding,
                GCS_METADATA_SFC_DIGEST: meta[SHA256_DIGEST],
            }

            if encryption_metadata:
                gcs_headers.update({
                    GCS_METADATA_ENCRYPTIONDATAPROP: json.dumps({
                        u'EncryptionMode': u'FullBlob',
                        u'WrappedContentKey': {
                            u'KeyId': u'symmKey1',
                            u'EncryptedKey': encryption_metadata.key,
                            u'Algorithm': u'AES_CBC_256'
                        },
                        u'EncryptionAgent': {
                            u'Protocol': '1.0',
                            u'EncryptionAlgorithm': u'AES_CBC_256',
                        },
                        u'ContentEncryptionIV': encryption_metadata.iv,
                        u'KeyWrappingMetadata': {
                            u'EncryptionLibrary': u'Java 5.3.0'
                        }
                    }),
                    GCS_METADATA_MATDESC_KEY: encryption_metadata.matdesc
                })

            with open(data_file, 'rb') as fd:
                try:
                    response = requests.put(
                        meta[u'presigned_url'],
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
                        meta[u'last_error'] = errh
                        meta[u'result_status'] = ResultStatus.NEED_RETRY
                        return
                    elif (errh.response.status_code == 400 and
                          (u'last_error' not in meta or meta[u'last_error'].response.status_code != 400)):
                        # Only attempt to renew urls if this isn't the second time this happens
                        meta[u'last_error'] = errh
                        meta[u'result_status'] = ResultStatus.RENEW_PRESIGNED_URL
                        return
                    # raise anything else
                    raise errh
                except requests.exceptions.Timeout as errt:
                    logger.debug("GCS file upload Timeout Error: %s", errt)
                    meta[u'last_error'] = errt
                    meta[u'result_status'] = ResultStatus.NEED_RETRY
                    return

            if meta[u'put_callback']:
                meta[u'put_callback'](
                    data_file,
                    meta[u'src_file_size'],
                    output_stream=meta[u'put_callback_output_stream'],
                    show_progress_bar=meta[u'show_progress_bar'])(
                    meta[u'src_file_size'])

            logger.debug(u'DONE putting a file')
            meta[u'dst_file_size'] = meta[u'upload_size']
            meta[u'result_status'] = ResultStatus.UPLOADED

            meta[GCS_FILE_HEADER_DIGEST] = gcs_headers[GCS_METADATA_SFC_DIGEST]
            meta[GCS_FILE_HEADER_CONTENT_LENGTH] = meta[u'upload_size']
            meta[GCS_FILE_HEADER_ENCRYPTION_METADATA] = \
                gcs_headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None)
        else:
            # Use the storage client to upload the object
            # Currently not supported, given that we can't obtain
            # location-scoped access tokens
            logger.error(u"GCS upload operation with an access token is "
                         u"currently unsupported")
            meta[u'result_status'] = ResultStatus.ERROR

    @staticmethod
    def _native_download_file(meta, full_dst_file_name, max_concurrency):
        """
        Downloads the remote object to local file
        :param meta: file meta object (contains credentials and remote location)
        :param full_dst_file_name: path of the local file to download to
        :param max_concurrency: (inapplicable to GCS)
        :return: None, if successful. Otherwise, throws Exception.
        """
        logger = getLogger(__name__)

        if meta.get(u'presigned_url', None):
            # Use presigned url to download the object
            try:
                response = requests.get(meta[u'presigned_url'], stream=True)
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
                    meta[u'last_error'] = errh
                    meta[u'result_status'] = ResultStatus.NEED_RETRY
                    return
                elif (errh.response.status_code == 400 and
                      (u'last_error' not in meta or meta[u'last_error'].errh.response.status_code != 400)):
                    # Only attempt to renew urls if this isn't the second time this happens
                    meta[u'last_error'] = errh
                    meta[u'result_status'] = ResultStatus.RENEW_PRESIGNED_URL
                    return
                # raise anything else
                raise errh
            except requests.exceptions.Timeout as errt:
                logger.debug("GCS file download Timeout Error: %s", errt)
                meta[u'last_error'] = errt
                meta[u'result_status'] = ResultStatus.NEED_RETRY
                return

            encryption_metadata = None

            if response.headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None):
                encryptiondata = json.loads(
                    response.headers[GCS_METADATA_ENCRYPTIONDATAPROP])

                if encryptiondata:
                    encryption_metadata = EncryptionMetadata(
                        key=encryptiondata[u'WrappedContentKey'][u'EncryptedKey'],
                        iv=encryptiondata[u'ContentEncryptionIV'],
                        matdesc=response.headers[GCS_METADATA_MATDESC_KEY]
                        if GCS_METADATA_MATDESC_KEY in response.headers
                        else None,
                    )

            # Sadly, we can only determine the src file size after we've
            # downloaded it, unlike the other cloud providers where the
            # metadata can be read beforehand.
            meta[u'src_file_size'] = os.path.getsize(full_dst_file_name)

            if meta[u'get_callback']:
                meta[u'get_callback'](
                    meta[u'src_file_name'],
                    meta[u'src_file_size'],
                    output_stream=meta[u'get_callback_output_stream'],
                    show_progress_bar=meta[u'show_progress_bar'])(
                    meta[u'src_file_size'])

            logger.debug(u'DONE getting a file')
            meta[u'result_status'] = ResultStatus.DOWNLOADED

            meta[GCS_FILE_HEADER_DIGEST] = response.headers.get(
                GCS_METADATA_SFC_DIGEST, None)
            meta[GCS_FILE_HEADER_CONTENT_LENGTH] = len(response.content)
            meta[GCS_FILE_HEADER_ENCRYPTION_METADATA] = encryption_metadata
        else:
            # Use the storage client to download the object
            # Currently not supported, given that we can't obtain
            # location-scoped access tokens
            logger.error(u"GCS download operation with an access token is "
                         u"currently unsupported")
            meta[u'result_status'] = ResultStatus.ERROR

    @staticmethod
    def get_file_header(meta, filename):
        """
        Gets the remote file metadata.
        :param meta: file meta object
        :return: the file header, with expected properties populated or None,
        based on how the request goes with the storage provider.
        """

        # Sometimes this method is called to verify that the file has indeed
        # been uploaded. In cases of presigned url, we have no way of verifying
        # that, except with the http status code of 200 which we have already
        # confirmed and set the meta[u'result_status'] = UPLOADED/DOWNLOADED.
        if meta.get(u'presigned_url', None):
            if meta.get(u'result_status', None) == ResultStatus.UPLOADED \
                    or meta.get(u'result_status', None) == ResultStatus.DOWNLOADED:
                return FileHeader(
                    digest=meta.get(
                        GCS_FILE_HEADER_DIGEST, None),
                    content_length=meta.get(
                        GCS_FILE_HEADER_CONTENT_LENGTH, None),
                    encryption_metadata=meta.get(
                        GCS_FILE_HEADER_ENCRYPTION_METADATA, None),
                )
            else:
                meta[u'result_status'] = ResultStatus.NOT_FOUND_FILE

        return FileHeader(
            digest=None,
            content_length=None,
            encryption_metadata=None
        )
