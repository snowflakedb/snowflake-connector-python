from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from io import IOBase
from logging import getLogger
from typing import TYPE_CHECKING, Any

import aiohttp

from ..compat import quote, urlparse
from ..constants import (
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_VALUE_OCTET_STREAM,
    FileHeader,
    ResultStatus,
)
from ..encryption_util import EncryptionMetadata
from ..s3_storage_client import (
    AMZ_IV,
    AMZ_KEY,
    AMZ_MATDESC,
    EXPIRED_TOKEN,
    META_PREFIX,
    SFC_DIGEST,
    UNSIGNED_PAYLOAD,
    S3Location,
)
from ..s3_storage_client import SnowflakeS3RestClient as SnowflakeS3RestClientSync
from ._storage_client import SnowflakeStorageClient as SnowflakeStorageClientAsync

if TYPE_CHECKING:  # pragma: no cover
    from ..file_transfer_agent import SnowflakeFileMeta, StorageCredential

logger = getLogger(__name__)


class SnowflakeS3RestClient(SnowflakeStorageClientAsync, SnowflakeS3RestClientSync):
    def __init__(
        self,
        meta: SnowflakeFileMeta,
        credentials: StorageCredential,
        stage_info: dict[str, Any],
        chunk_size: int,
        use_accelerate_endpoint: bool | None = None,
        use_s3_regional_url: bool = False,
        unsafe_file_write: bool = False,
    ) -> None:
        """Rest client for S3 storage.

        Args:
            stage_info:
        """
        SnowflakeStorageClientAsync.__init__(
            self,
            meta=meta,
            stage_info=stage_info,
            chunk_size=chunk_size,
            credentials=credentials,
            unsafe_file_write=unsafe_file_write,
        )
        # Signature version V4
        # Addressing style Virtual Host
        self.region_name: str = stage_info["region"]
        # Multipart upload only
        self.upload_id: str | None = None
        self.etags: list[str] | None = None
        self.s3location: S3Location = (
            SnowflakeS3RestClient._extract_bucket_name_and_path(
                self.stage_info["location"]
            )
        )
        self.use_s3_regional_url = (
            use_s3_regional_url
            or "useS3RegionalUrl" in stage_info
            and stage_info["useS3RegionalUrl"]
            or "useRegionalUrl" in stage_info
            and stage_info["useRegionalUrl"]
        )
        self.location_type = stage_info.get("locationType")

        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        self.endpoint: str | None = None
        if stage_info["endPoint"]:
            self.endpoint = (
                f"https://{self.s3location.bucket_name}." + stage_info["endPoint"]
            )

    async def _send_request_with_authentication_and_retry(
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

        def generate_authenticated_url_and_args_v4() -> tuple[str, dict[str, bytes]]:
            t = datetime.now(timezone.utc).replace(tzinfo=None)
            amzdate = t.strftime("%Y%m%dT%H%M%SZ")
            short_amzdate = amzdate[:8]
            x_amz_headers["x-amz-date"] = amzdate
            x_amz_headers["x-amz-security-token"] = self.credentials.creds.get(
                "AWS_TOKEN", ""
            )

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

            if ignore_content_encoding:
                rest_args["auto_decompress"] = False

            return url, rest_args

        return await self._send_request_with_retry(
            verb, generate_authenticated_url_and_args_v4, retry_id
        )

    async def get_file_header(self, filename: str) -> FileHeader | None:
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
        response = await self._send_request_with_authentication_and_retry(
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

    # for multi-chunk file transfer
    async def _initiate_multipart_upload(self) -> None:
        query_parts = (("uploads", ""),)
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        query_string = self._construct_query_string(query_parts)
        url = self.endpoint + f"/{path}?{query_string}"
        s3_metadata = self._prepare_file_metadata()
        # initiate multipart upload
        retry_id = "Initiate"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry(
            url=url,
            verb="POST",
            retry_id=retry_id,
            x_amz_headers=s3_metadata,
            headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
            query_parts=dict(query_parts),
        )
        if response.status == 200:
            self.upload_id = ET.fromstring(await response.read())[2].text
            self.etags = [None] * self.num_of_chunks
        else:
            response.raise_for_status()

    async def _upload_chunk(self, chunk_id: int, chunk: bytes) -> None:
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        url = self.endpoint + f"/{path}"

        if self.num_of_chunks == 1:  # single request
            s3_metadata = self._prepare_file_metadata()
            response = await self._send_request_with_authentication_and_retry(
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
            response = await self._send_request_with_authentication_and_retry(
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

    async def _complete_multipart_upload(self) -> None:
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
        response = await self._send_request_with_authentication_and_retry(
            url=url,
            verb="POST",
            retry_id=retry_id,
            payload=ET.tostring(root),
            query_parts=dict(query_parts),
        )
        response.raise_for_status()

    async def _abort_multipart_upload(self) -> None:
        if self.upload_id is None:
            return
        query_parts = (("uploadId", self.upload_id),)
        path = quote(self.s3location.path + self.meta.dst_file_name.lstrip("/"))
        query_string = self._construct_query_string(query_parts)
        url = self.endpoint + f"/{path}?{query_string}"

        retry_id = "Abort"
        self.retry_count[retry_id] = 0
        response = await self._send_request_with_authentication_and_retry(
            url=url,
            verb="DELETE",
            retry_id=retry_id,
            query_parts=dict(query_parts),
        )
        response.raise_for_status()

    async def download_chunk(self, chunk_id: int) -> None:
        logger.debug(f"Downloading chunk {chunk_id}")
        path = quote(self.s3location.path + self.meta.src_file_name.lstrip("/"))
        url = self.endpoint + f"/{path}"
        if self.num_of_chunks == 1:
            response = await self._send_request_with_authentication_and_retry(
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
                _range = f"{chunk_id * chunk_size}-{(chunk_id + 1) * chunk_size - 1}"
            else:
                _range = f"{chunk_id * chunk_size}-"

            response = await self._send_request_with_authentication_and_retry(
                url=url,
                verb="GET",
                retry_id=chunk_id,
                headers={"Range": f"bytes={_range}"},
            )
            if response.status in (200, 206):
                self.write_downloaded_chunk(chunk_id, await response.read())
            response.raise_for_status()

    async def _get_bucket_accelerate_config(self, bucket_name: str) -> bool:
        query_parts = (("accelerate", ""),)
        query_string = self._construct_query_string(query_parts)
        url = f"https://{bucket_name}.s3.amazonaws.com/?{query_string}"
        retry_id = "accelerate"
        self.retry_count[retry_id] = 0

        response = await self._send_request_with_authentication_and_retry(
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

    async def transfer_accelerate_config(
        self, use_accelerate_endpoint: bool | None = None
    ) -> bool:
        # accelerate cannot be used in China and us government
        if self.region_name and self.region_name.startswith("cn-"):
            self.endpoint = (
                f"https://{self.s3location.bucket_name}."
                f"s3.{self.region_name}.amazonaws.com.cn"
            )
            return False
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
                if str(self.s3location.bucket_name).lower().startswith("sfc-"):
                    # SNOW-2324060: no s3:GetAccelerateConfiguration and no intention to add either
                    # for internal stage, thus previously the client got HTTP403 on /accelerate call
                    logger.debug(
                        "Not attempting to get bucket transfer accelerate endpoint for internal stage."
                    )
                    use_accelerate_endpoint = False
                else:
                    use_accelerate_endpoint = await self._get_bucket_accelerate_config(
                        self.s3location.bucket_name
                    )

            if use_accelerate_endpoint:
                self.endpoint = (
                    f"https://{self.s3location.bucket_name}.s3-accelerate.amazonaws.com"
                )
            else:
                self.endpoint = (
                    f"https://{self.s3location.bucket_name}.s3.amazonaws.com"
                )
            logger.debug(f"Using {self.endpoint} as storage endpoint.")
            return use_accelerate_endpoint

    async def _has_expired_token(self, response: aiohttp.ClientResponse) -> bool:
        """Extract error code and error message from the S3's error response.
        Expected format:
        https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses
        Args:
            response: Rest error response in XML format
        Returns: True if the error response is caused by token expiration
        """
        if response.status != 400:
            return False
        # Read body once; avoid a second read which can raise RuntimeError("Connection closed.")
        try:
            message = await response.text()
        except RuntimeError as e:
            logger.debug(
                "S3 token-expiry check: failed to read error body, treating as not expired. error=%s",
                type(e),
            )
            return False
        if not message:
            logger.debug(
                "S3 token-expiry check: empty error body, treating as not expired"
            )
            return False
        try:
            err = ET.fromstring(message)
        except ET.ParseError:
            logger.debug(
                "S3 token-expiry check: non-XML error body (len=%d), treating as not expired.",
                len(message),
            )
            return False
        code = err.find("Code")
        return code is not None and code.text == EXPIRED_TOKEN
