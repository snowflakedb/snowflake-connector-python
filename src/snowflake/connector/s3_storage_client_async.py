#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from io import IOBase
from logging import getLogger

import aiohttp

from .compat import quote, urlparse
from .constants import (
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_VALUE_OCTET_STREAM,
    EncryptionMetadata,
    FileHeader,
    ResultStatus,
)
from .event_loop_runner import LOOP_RUNNER
from .s3_storage_client import (
    AMZ_IV,
    AMZ_KEY,
    AMZ_MATDESC,
    EXPIRED_TOKEN,
    META_PREFIX,
    SFC_DIGEST,
    UNSIGNED_PAYLOAD,
    SnowflakeS3RestClient,
)
from .storage_client_async import SnowflakeStorageClientAsync

logger = getLogger(__name__)


# YICHUAN: Prioritize methods inherited SnowflakeStorageClientAsync because it will only override what it needs to
# For the most part, this class overrides private methods with "_async" suffix that will be called by public methods
# in SnowflakeStorageClientAsync
class SnowflakeS3RestClientAsync(SnowflakeStorageClientAsync, SnowflakeS3RestClient):
    def transfer_accelerate_config(
        self, use_accelerate_endpoint: bool | None = None
    ) -> bool:
        # if self.endpoint has been set, e.g. by metadata, no more config is needed.
        if self.endpoint is not None:
            return self.endpoint.find("s3-accelerate.amazonaws.com") >= 0
        if self.use_s3_regional_url:
            self.endpoint = (
                f"https://{self.s3location.bucket_name}."
                f"s3.{self.region_name}.amazonaws.com"
            )
            return False
        else:
            if use_accelerate_endpoint is None:
                use_accelerate_endpoint = LOOP_RUNNER.run_coro(
                    self._get_bucket_accelerate_config_async(
                        self.s3location.bucket_name
                    )
                )

            if use_accelerate_endpoint:
                self.endpoint = (
                    f"https://{self.s3location.bucket_name}.s3-accelerate.amazonaws.com"
                )
            else:
                self.endpoint = (
                    f"https://{self.s3location.bucket_name}.s3.amazonaws.com"
                )
            return use_accelerate_endpoint

    async def _has_expired_token_async(self, response: aiohttp.ClientResponse) -> bool:
        """Extract error code and error message from the S3's error response.

        Expected format:
        https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses

        Args:
            response: Rest error response in XML format

        Returns: True if the error response is caused by token expiration

        """
        if response.status != 400:
            return False
        message = await response.text()
        if not message or message.isspace():
            return False
        err = ET.fromstring(message)
        return err.find("Code").text == EXPIRED_TOKEN

    async def _send_request_with_authentication_and_retry_async(
        self,
        url: str,
        verb: str,
        retry_id: int | str,
        query_parts: dict[str, str] | None = None,
        x_amz_headers: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        payload: bytes | bytearray | IOBase | None = None,
        unsigned_payload: bool = False,
        ignore_content_encoding: bool = False,
    ) -> aiohttp.ClientResponse:
        if x_amz_headers is None:
            x_amz_headers = {}
        if headers is None:
            headers = {}
        if payload is None:
            payload = b""
        if query_parts is None:
            query_parts = {}
        parsed_url = urlparse(url)
        x_amz_headers["x-amz-security-token"] = self.credentials.creds.get(
            "AWS_TOKEN", ""
        )
        x_amz_headers["host"] = parsed_url.hostname
        if unsigned_payload:
            x_amz_headers["x-amz-content-sha256"] = UNSIGNED_PAYLOAD
        else:
            x_amz_headers["x-amz-content-sha256"] = (
                SnowflakeS3RestClient._hash_bytes_hex(payload).lower().decode()
            )

        def generate_authenticated_url_and_args_v4() -> tuple[bytes, dict[str, bytes]]:
            t = datetime.utcnow()
            amzdate = t.strftime("%Y%m%dT%H%M%SZ")
            short_amzdate = amzdate[:8]
            x_amz_headers["x-amz-date"] = amzdate

            (
                canonical_request,
                signed_headers,
            ) = self._construct_canonical_request_and_signed_headers(
                verb=verb,
                canonical_uri_parameter=parsed_url.path
                + (f";{parsed_url.params}" if parsed_url.params else ""),
                query_parts=query_parts,
                canonical_headers=x_amz_headers,
                payload_hash=x_amz_headers["x-amz-content-sha256"],
            )
            string_to_sign, scope = self._construct_string_to_sign(
                self.region_name,
                "s3",
                amzdate,
                short_amzdate,
                self._hash_bytes_hex(canonical_request.encode("utf-8")).lower(),
            )
            kDate = self._sign_bytes(
                ("AWS4" + self.credentials.creds["AWS_SECRET_KEY"]).encode("utf-8"),
                short_amzdate,
            )
            kRegion = self._sign_bytes(kDate, self.region_name)
            kService = self._sign_bytes(kRegion, "s3")
            signing_key = self._sign_bytes(kService, "aws4_request")

            signature = self._sign_bytes_hex(signing_key, string_to_sign).lower()
            authorization_header = (
                "AWS4-HMAC-SHA256 "
                + f"Credential={self.credentials.creds['AWS_KEY_ID']}/{scope}, "
                + f"SignedHeaders={signed_headers}, "
                + f"Signature={signature.decode('utf-8')}"
            )
            headers.update(x_amz_headers)
            headers["Authorization"] = authorization_header
            rest_args = {"headers": headers}

            if payload:
                rest_args["data"] = payload

            # FORMERLY:
            # add customized hook: to remove content-encoding from response.

            # YICHUAN: aiohttp doesn't provide hooks the same way requests does, but we removed the Content-Encoding
            # header was to prevent server data from being decompressed, and we can achieve the same effect here
            if ignore_content_encoding:
                # rest_args["hooks"] = {"response": remove_content_encoding}
                rest_args["auto_decompress"] = False

            # YICHUAN: Don't encode url, aiohttp does not play nice with byte strings
            return url, rest_args

        return await self._send_request_with_retry_async(
            verb, generate_authenticated_url_and_args_v4, retry_id
        )

    async def get_file_header_async(self, filename: str) -> FileHeader | None:
        """Gets the metadata of file in specified location.

        Args:
            filename: Name of remote file.

        Returns:
            None if HEAD returns 404, otherwise a FileHeader instance populated
            with metadata
        """
        path = quote(self.s3location.path + filename.lstrip("/"))
        url = self.endpoint + f"/{path}"

        retry_id = "HEAD"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry_async(
            url=url, verb="HEAD", retry_id=retry_id
        )
        if response.status == 200:
            self.meta.result_status = ResultStatus.UPLOADED
            metadata = response.headers
            encryption_metadata = (
                EncryptionMetadata(
                    key=metadata.get(META_PREFIX + AMZ_KEY),
                    iv=metadata.get(META_PREFIX + AMZ_IV),
                    matdesc=metadata.get(META_PREFIX + AMZ_MATDESC),
                )
                if metadata.get(META_PREFIX + AMZ_KEY)
                else None
            )
            return FileHeader(
                digest=metadata.get(META_PREFIX + SFC_DIGEST),
                content_length=int(metadata.get("Content-Length")),
                encryption_metadata=encryption_metadata,
            )
        elif response.status == 404:
            logger.debug(
                f"not found. bucket: {self.s3location.bucket_name}, path: {path}"
            )
            self.meta.result_status = ResultStatus.NOT_FOUND_FILE
            return None
        else:
            response.raise_for_status()

    async def _initiate_multipart_upload_async(self) -> None:
        query_parts = (("uploads", ""),)
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        query_string = self._construct_query_string(query_parts)
        url = self.endpoint + f"/{path}?{query_string}"
        s3_metadata = self._prepare_file_metadata()
        # initiate multipart upload
        retry_id = "Initiate"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry_async(
            url=url,
            verb="POST",
            retry_id=retry_id,
            x_amz_headers=s3_metadata,
            headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
            query_parts=dict(query_parts),
        )
        if response.status == 200:
            self.upload_id = ET.fromstring(await response.text())[2].text
            self.etags = [None] * self.num_of_chunks
        else:
            response.raise_for_status()

    async def _upload_chunk_async(self, chunk_id: int, chunk: bytes) -> None:
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        url = self.endpoint + f"/{path}"

        if self.num_of_chunks == 1:  # single request
            s3_metadata = self._prepare_file_metadata()
            response = await self._send_request_with_authentication_and_retry_async(
                url=url,
                verb="PUT",
                retry_id=chunk_id,
                payload=chunk,
                x_amz_headers=s3_metadata,
                headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
                unsigned_payload=True,
            )
            response.raise_for_status()
        else:
            # multipart PUT
            query_parts = (
                ("partNumber", str(chunk_id + 1)),
                ("uploadId", self.upload_id),
            )
            query_string = self._construct_query_string(query_parts)
            chunk_url = f"{url}?{query_string}"
            response = await self._send_request_with_authentication_and_retry_async(
                url=chunk_url,
                verb="PUT",
                retry_id=chunk_id,
                payload=chunk,
                unsigned_payload=True,
                query_parts=dict(query_parts),
            )
            if response.status == 200:
                self.etags[chunk_id] = response.headers["ETag"]
            response.raise_for_status()

    async def _complete_multipart_upload_async(self) -> None:
        query_parts = (("uploadId", self.upload_id),)
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        query_string = self._construct_query_string(query_parts)
        url = self.endpoint + f"/{path}?{query_string}"
        logger.debug("Initiating multipart upload complete")
        # Complete multipart upload
        root = ET.Element("CompleteMultipartUpload")
        for idx, etag_str in enumerate(self.etags):
            part = ET.Element("Part")
            etag = ET.Element("ETag")
            etag.text = etag_str
            part.append(etag)
            part_number = ET.Element("PartNumber")
            part_number.text = str(idx + 1)
            part.append(part_number)
            root.append(part)
        retry_id = "Complete"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry_async(
            url=url,
            verb="POST",
            retry_id=retry_id,
            payload=ET.tostring(root),
            query_parts=dict(query_parts),
        )
        response.raise_for_status()

    async def _abort_multipart_upload_async(self) -> None:
        if self.upload_id is None:
            return
        query_parts = (("uploadId", self.upload_id),)
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        query_string = self._construct_query_string(query_parts)
        url = self.endpoint + f"/{path}?{query_string}"

        retry_id = "Abort"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry_async(
            url=url,
            verb="DELETE",
            retry_id=retry_id,
            query_parts=dict(query_parts),
        )
        response.raise_for_status()

    # YICHUAN: aiohttp version of S3RestClient.download_chunk, invoked by SnowflakeStorageClientAsync.download_chunk
    async def _download_chunk_async(self, chunk_id: int) -> None:
        logger.debug(f"Downloading chunk {chunk_id}")
        path = quote(self.s3location.path + self.meta.src_file_name.lstrip("/"))
        url = self.endpoint + f"/{path}"
        if self.num_of_chunks == 1:
            response = await self._send_request_with_authentication_and_retry_async(
                url=url,
                verb="GET",
                retry_id=chunk_id,
                ignore_content_encoding=True,
            )
            if response.status == 200:
                self.write_downloaded_chunk(0, await response.read())
                self.meta.result_status = ResultStatus.DOWNLOADED
            response.raise_for_status()
        else:
            chunk_size = self.chunk_size
            if chunk_id < self.num_of_chunks - 1:
                _range = f"{chunk_id * chunk_size}-{(chunk_id+1)*chunk_size-1}"
            else:
                _range = f"{chunk_id * chunk_size}-"

            response = await self._send_request_with_authentication_and_retry_async(
                url=url,
                verb="GET",
                retry_id=chunk_id,
                headers={"Range": f"bytes={_range}"},
            )
            if response.status in (200, 206):
                self.write_downloaded_chunk(chunk_id, await response.read())
            response.raise_for_status()

    async def _get_bucket_accelerate_config_async(self, bucket_name: str) -> bool:
        query_parts = (("accelerate", ""),)
        query_string = self._construct_query_string(query_parts)
        url = f"https://{bucket_name}.s3.amazonaws.com/?{query_string}"
        retry_id = "accelerate"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry_async(
            url=url, verb="GET", retry_id=retry_id, query_parts=dict(query_parts)
        )
        if response.status == 200:
            config = ET.fromstring(await response.text())
            namespace = config.tag[: config.tag.index("}") + 1]
            statusTag = f"{namespace}Status"
            found = config.find(statusTag)
            use_accelerate_endpoint = (
                False if found is None else (found.text == "Enabled")
            )
            logger.debug(f"use_accelerate_endpoint: {use_accelerate_endpoint}")
            return use_accelerate_endpoint
        return False
