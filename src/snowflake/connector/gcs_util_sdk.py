#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import json
import os
from collections import namedtuple
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict, Optional

from .compat import quote
from .constants import HTTP_HEADER_CONTENT_ENCODING, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata
from .vendored import requests

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent_sdk import SnowflakeFileMeta

logger = getLogger(__name__)

GCS_METADATA_PREFIX = "x-goog-meta-"
GCS_METADATA_SFC_DIGEST = GCS_METADATA_PREFIX + "sfc-digest"
GCS_METADATA_MATDESC_KEY = GCS_METADATA_PREFIX + "matdesc"
GCS_METADATA_ENCRYPTIONDATAPROP = GCS_METADATA_PREFIX + "encryptiondata"
GCS_FILE_HEADER_DIGEST = "gcs-file-header-digest"
GCS_FILE_HEADER_CONTENT_LENGTH = "gcs-file-header-content-length"
GCS_FILE_HEADER_ENCRYPTION_METADATA = "gcs-file-header-encryption-metadata"
CONTENT_CHUNK_SIZE = 10 * 1024

"""
Gcs Location: Gcs bucket name + path
"""
GcsLocation = namedtuple(
    "GcsLocation", ["bucket_name", "path"]  # Gcs bucket name  # Gcs path name
)


class SnowflakeGCSUtil:
    """GCS Utility class."""

    @staticmethod
    def create_client(
        stage_info: Dict[str, Any],
        use_accelerate_endpoint: bool = False,
        use_s3_regional_url: bool = False,
        s3_connection_pool_size: int = 1,
    ) -> Optional[str]:
        """Creates a client object with given stage credentials.

        Args:
            stage_info: Access credentials and info of a stage.
            use_accelerate_endpoint: Whether to use an accelerated endpoint? This is not applicable to GCS.

        Returns:
            The client to communicate with GCS.
        """
        stage_credentials = stage_info["creds"]
        security_token = stage_credentials.get("GCS_ACCESS_TOKEN")

        if security_token:
            logger.debug(f"len(GCS_ACCESS_TOKEN): {len(security_token)}")
            logger.debug("Access token is saved as client for renew")
            client = security_token

        else:
            logger.debug(
                "No access token received from GS, constructing anonymous client"
            )
            client = None

        return client

    @staticmethod
    def upload_file(
        data_file: str,
        meta: "SnowflakeFileMeta",
        encryption_metadata: Any,
        max_concurrency: int,
        multipart_threshold: int,
    ):
        """Uploads the local file to GCS's blob storage.

        Args:
            data_file: File path on local system.
            meta: The File meta object (contains credentials and remote location).
            encryption_metadata: Encryption metadata to be set on object.
            max_concurrency: The maximum number of threads to used to upload. Not applicable to GCS.
            multipart_threshold: The number of bytes after which size a file should be uploaded concurrently in chunks.
                Not applicable to GCS.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None.
        """
        upload_url = meta.presigned_url
        access_token: Optional[str] = None

        if not upload_url:
            upload_url = SnowflakeGCSUtil.generate_file_url(
                meta.client_meta.stage_info["location"], meta.dst_file_name.lstrip("/")
            )
            access_token = meta.client_meta.cloud_client

        content_encoding = ""
        if meta.dst_compression_type is not None:
            content_encoding = meta.dst_compression_type.name.lower()

        # We set the contentEncoding to blank for GZIP files. We don't
        # want GCS to think our gzip files are gzips because it makes
        # them download uncompressed, and none of the other providers do
        # that. There's essentially no way for us to prevent that
        # behavior. Bad Google.
        if content_encoding and content_encoding == "gzip":
            content_encoding = ""

        gcs_headers = {
            HTTP_HEADER_CONTENT_ENCODING: content_encoding,
            GCS_METADATA_SFC_DIGEST: meta.sha256_digest,
        }
        if access_token:
            gcs_headers.update({"Authorization": f"Bearer {access_token}"})

        if encryption_metadata:
            gcs_headers.update(
                {
                    GCS_METADATA_ENCRYPTIONDATAPROP: json.dumps(
                        {
                            "EncryptionMode": "FullBlob",
                            "WrappedContentKey": {
                                "KeyId": "symmKey1",
                                "EncryptedKey": encryption_metadata.key,
                                "Algorithm": "AES_CBC_256",
                            },
                            "EncryptionAgent": {
                                "Protocol": "1.0",
                                "EncryptionAlgorithm": "AES_CBC_256",
                            },
                            "ContentEncryptionIV": encryption_metadata.iv,
                            "KeyWrappingMetadata": {"EncryptionLibrary": "Java 5.3.0"},
                        }
                    ),
                    GCS_METADATA_MATDESC_KEY: encryption_metadata.matdesc,
                }
            )

        try:
            upload_src = None
            if meta.src_stream is None:
                upload_src = open(data_file, "rb")
            else:
                upload_src = meta.real_src_stream or meta.src_stream

            response = requests.put(
                url=upload_url, data=upload_src, headers=gcs_headers
            )
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
                meta.last_error = errh
                meta.result_status = ResultStatus.NEED_RETRY
                return
            elif (
                (not access_token)
                and errh.response.status_code == 400
                and (
                    meta.last_error is None
                    or meta.last_error.response.status_code != 400
                )
            ):
                # Only attempt to renew urls if this isn't the second time this happens
                meta.last_error = errh
                meta.result_status = ResultStatus.RENEW_PRESIGNED_URL
                return
            elif access_token and SnowflakeGCSUtil.is_token_expired(errh.response):
                meta.last_error = errh
                meta.result_status = ResultStatus.RENEW_TOKEN
                return
            # raise anything else
            raise errh
        except requests.exceptions.Timeout as errt:
            logger.debug(f"GCS file upload Timeout Error: {errt}")
            meta.last_error = errt
            meta.result_status = ResultStatus.NEED_RETRY
            return
        finally:
            if meta.src_stream is None:
                upload_src.close()

        if meta.put_callback is not None:
            meta.put_callback(
                data_file,
                meta.src_file_size,
                output_stream=meta.put_callback_output_stream,
                show_progress_bar=meta.show_progress_bar,
            )(meta.src_file_size)

        logger.debug("DONE putting a file")
        meta.dst_file_size = meta.upload_size
        meta.result_status = ResultStatus.UPLOADED

        meta.gcs_file_header_digest = gcs_headers[GCS_METADATA_SFC_DIGEST]
        meta.gcs_file_header_content_length = meta.upload_size
        meta.gcs_file_header_encryption_metadata = json.loads(
            gcs_headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, "null")
        )

    @staticmethod
    def _native_download_file(
        meta: "SnowflakeFileMeta", full_dst_file_name: str, max_concurrency: int
    ):
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
        download_url = meta.presigned_url
        gcs_headers = None
        access_token: Optional[str] = None

        if not download_url:
            download_url = SnowflakeGCSUtil.generate_file_url(
                meta.client_meta.stage_info["location"], meta.src_file_name.lstrip("/")
            )
            access_token = meta.client_meta.cloud_client
            gcs_headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(download_url, headers=gcs_headers, stream=True)
            response.raise_for_status()

            with open(full_dst_file_name, "wb") as fd:
                for chunk in response.raw.stream(
                    CONTENT_CHUNK_SIZE, decode_content=False
                ):
                    fd.write(chunk)
        except requests.exceptions.HTTPError as errh:
            logger.debug(f"GCS file download Http Error: {errh}")
            # Presigned urls can be generated for any xml-api operation
            # offered by GCS. Hence the error codes expected are similar
            # to xml api.
            # https://cloud.google.com/storage/docs/xml-api/reference-status

            # According to the above resource, GCS recommends retrying
            # for the following error codes.
            if errh.response.status_code in [403, 408, 429, 500, 503]:
                meta.last_error = errh
                meta.result_status = ResultStatus.NEED_RETRY
                return
            elif (
                (not access_token)
                and errh.response.status_code == 400
                and (
                    meta.last_error is None
                    or meta.last_error.errh.response.status_code != 400
                )
            ):
                # Only attempt to renew urls if this isn't the second time this happens
                meta.last_error = errh
                meta.result_status = ResultStatus.RENEW_PRESIGNED_URL
                return
            elif access_token and SnowflakeGCSUtil.is_token_expired(errh.response):
                meta.last_error = errh
                meta.result_status = ResultStatus.RENEW_TOKEN
                return
            # raise anything else
            raise errh
        except requests.exceptions.Timeout as errt:
            logger.debug(f"GCS file download Timeout Error: {errt}")
            meta.last_error = errt
            meta.result_status = ResultStatus.NEED_RETRY
            return

        encryption_metadata = None

        if response.headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None):
            encryptiondata = json.loads(
                response.headers[GCS_METADATA_ENCRYPTIONDATAPROP]
            )

            if encryptiondata:
                encryption_metadata = EncryptionMetadata(
                    key=encryptiondata["WrappedContentKey"]["EncryptedKey"],
                    iv=encryptiondata["ContentEncryptionIV"],
                    matdesc=response.headers[GCS_METADATA_MATDESC_KEY]
                    if GCS_METADATA_MATDESC_KEY in response.headers
                    else None,
                )

        # Sadly, we can only determine the src file size after we've
        # downloaded it, unlike the other cloud providers where the
        # metadata can be read beforehand.
        meta.src_file_size = os.path.getsize(full_dst_file_name)

        if meta.get_callback:
            meta.get_callback(
                meta.src_file_name,
                meta.src_file_size,
                output_stream=meta.get_callback_output_stream,
                show_progress_bar=meta.show_progress_bar,
            )(meta.src_file_size)

        logger.debug("DONE getting a file")
        meta.result_status = ResultStatus.DOWNLOADED

        meta.gcs_file_header_digest = response.headers.get(GCS_METADATA_SFC_DIGEST)
        meta.gcs_file_header_content_length = len(response.content)
        meta.gcs_file_header_encryption_metadata = encryption_metadata

    @staticmethod
    def get_file_header(
        meta: "SnowflakeFileMeta", filename: str
    ) -> Optional[FileHeader]:
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
            confirmed and set the meta.result_status = UPLOADED/DOWNLOADED.
        """
        if (
            meta.result_status == ResultStatus.UPLOADED
            or meta.result_status == ResultStatus.DOWNLOADED
        ):
            return FileHeader(
                digest=meta.gcs_file_header_digest,
                content_length=meta.gcs_file_header_content_length,
                encryption_metadata=meta.gcs_file_header_encryption_metadata,
            )
        else:
            if meta.presigned_url:
                meta.result_status = ResultStatus.NOT_FOUND_FILE
            else:
                url = SnowflakeGCSUtil.generate_file_url(
                    meta.client_meta.stage_info["location"], filename.lstrip("/")
                )
                access_token: str = meta.client_meta.cloud_client
                gcs_headers = {"Authorization": f"Bearer {access_token}"}
                try:
                    response = requests.head(url, headers=gcs_headers)
                    response.raise_for_status()

                    digest = response.headers.get(GCS_METADATA_SFC_DIGEST, None)
                    content_length = response.headers.get("content-length", None)
                    if response.headers.get(GCS_METADATA_ENCRYPTIONDATAPROP, None):
                        encryption_data = json.loads(
                            response.headers[GCS_METADATA_ENCRYPTIONDATAPROP]
                        )

                        if encryption_data:
                            encryption_metadata = EncryptionMetadata(
                                key=encryption_data["WrappedContentKey"][
                                    "EncryptedKey"
                                ],
                                iv=encryption_data["ContentEncryptionIV"],
                                matdesc=response.headers[GCS_METADATA_MATDESC_KEY]
                                if GCS_METADATA_MATDESC_KEY in response.headers
                                else None,
                            )
                    meta.result_status = ResultStatus.UPLOADED
                    return FileHeader(
                        digest=digest,
                        content_length=content_length,
                        encryption_metadata=encryption_metadata,
                    )
                except requests.exceptions.HTTPError as errh:
                    if errh.response.status_code in [403, 408, 429, 500, 503]:
                        meta.last_error = errh
                        meta.result_status = ResultStatus.NEED_RETRY
                        return
                    if errh.response.status_code == 404:
                        meta.result_status = ResultStatus.NOT_FOUND_FILE
                    elif SnowflakeGCSUtil.is_token_expired(errh.response):
                        meta.last_error = errh
                        meta.result_status = ResultStatus.RENEW_TOKEN
                    else:
                        meta.last_error = errh
                        meta.result_status = ResultStatus.ERROR
                        raise errh

        return FileHeader(
            digest=None,
            content_length=None,
            encryption_metadata=None,
        )

    @staticmethod
    def extract_bucket_name_and_path(stage_location: str) -> GcsLocation:
        container_name = stage_location
        path = ""

        # split stage location as bucket name and path
        if "/" in stage_location:
            container_name = stage_location[0 : stage_location.index("/")]
            path = stage_location[stage_location.index("/") + 1 :]
            if path and not path.endswith("/"):
                path += "/"

        return GcsLocation(bucket_name=container_name, path=path)

    @staticmethod
    def generate_file_url(stage_location: str, filename: str) -> str:
        gcs_location = SnowflakeGCSUtil.extract_bucket_name_and_path(stage_location)
        full_file_path = f"{gcs_location.path}{filename}"
        return f"https://storage.googleapis.com/{gcs_location.bucket_name}/{quote(full_file_path)}"

    @staticmethod
    def is_token_expired(response: Any) -> bool:
        # Looking further as java gcs client code, I find that token only need refresh if error is 401
        return response.status_code == 401
