from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from logging import getLogger
from random import choice
from string import hexdigits
from typing import TYPE_CHECKING, Any

import aiohttp

from ..azure_storage_client import (
    SnowflakeAzureRestClient as SnowflakeAzureRestClientSync,
)
from ..compat import quote
from ..constants import FileHeader, ResultStatus
from ..encryption_util import EncryptionMetadata
from ..util_text import get_md5_for_integrity
from ._storage_client import SnowflakeStorageClient as SnowflakeStorageClientAsync

if TYPE_CHECKING:  # pragma: no cover
    from ..file_transfer_agent import SnowflakeFileMeta, StorageCredential

from ..azure_storage_client import (
    ENCRYPTION_DATA,
    MATDESC,
    SFCDIGEST,
    TOKEN_EXPIRATION_ERR_MESSAGE,
)

logger = getLogger(__name__)


class SnowflakeAzureRestClient(
    SnowflakeStorageClientAsync, SnowflakeAzureRestClientSync
):
    def __init__(
        self,
        meta: SnowflakeFileMeta,
        credentials: StorageCredential | None,
        chunk_size: int,
        stage_info: dict[str, Any],
        unsafe_file_write: bool = False,
    ) -> None:
        SnowflakeAzureRestClientSync.__init__(
            self,
            meta=meta,
            stage_info=stage_info,
            chunk_size=chunk_size,
            credentials=credentials,
            unsafe_file_write=unsafe_file_write,
        )

    async def _has_expired_token(self, response: aiohttp.ClientResponse) -> bool:
        return response.status == 403 and any(
            message in response.reason for message in TOKEN_EXPIRATION_ERR_MESSAGE
        )

    async def _send_request_with_authentication_and_retry(
        self,
        verb: str,
        url: str,
        retry_id: int | str,
        headers: dict[str, Any] = None,
        data: bytes = None,
    ) -> aiohttp.ClientResponse:
        if not headers:
            headers = {}

        def generate_authenticated_url_and_rest_args() -> tuple[str, dict[str, Any]]:
            curtime = datetime.now(timezone.utc).replace(tzinfo=None)
            timestamp = curtime.strftime("YYYY-MM-DD")
            sas_token = self.credentials.creds["AZURE_SAS_TOKEN"]
            if sas_token and sas_token.startswith("?"):
                sas_token = sas_token[1:]
            if "?" in url:
                _url = url + "&" + sas_token
            else:
                _url = url + "?" + sas_token
            headers["Date"] = timestamp
            rest_args = {"headers": headers}
            if data:
                rest_args["data"] = data
            return _url, rest_args

        return await self._send_request_with_retry(
            verb, generate_authenticated_url_and_rest_args, retry_id
        )

    async def get_file_header(self, filename: str) -> FileHeader | None:
        """Gets Azure file properties."""
        container_name = quote(self.azure_location.container_name)
        path = quote(self.azure_location.path) + quote(filename)
        meta = self.meta
        # HTTP HEAD request
        url = f"https://{self.storage_account}.blob.{self.endpoint}/{container_name}/{path}"
        retry_id = "HEAD"
        self.retry_count[retry_id] = 0
        r = await self._send_request_with_authentication_and_retry(
            "HEAD", url, retry_id
        )
        if r.status == 200:
            meta.result_status = ResultStatus.UPLOADED
            enc_data_str = r.headers.get(ENCRYPTION_DATA)
            encryption_data = None if enc_data_str is None else json.loads(enc_data_str)
            encryption_metadata = (
                None
                if not encryption_data
                else EncryptionMetadata(
                    key=encryption_data["WrappedContentKey"]["EncryptedKey"],
                    iv=encryption_data["ContentEncryptionIV"],
                    matdesc=r.headers.get(MATDESC),
                )
            )
            return FileHeader(
                digest=r.headers.get(SFCDIGEST),
                content_length=int(r.headers.get("Content-Length")),
                encryption_metadata=encryption_metadata,
            )
        elif r.status == 404:
            meta.result_status = ResultStatus.NOT_FOUND_FILE
            return FileHeader(
                digest=None, content_length=None, encryption_metadata=None
            )
        else:
            r.raise_for_status()

    async def _initiate_multipart_upload(self) -> None:
        self.block_ids = [
            "".join(choice(hexdigits) for _ in range(20))
            for _ in range(self.num_of_chunks)
        ]

    async def _upload_chunk(self, chunk_id: int, chunk: bytes) -> None:
        container_name = quote(self.azure_location.container_name)
        path = quote(self.azure_location.path + self.meta.dst_file_name.lstrip("/"))

        if self.num_of_chunks > 1:
            block_id = self.block_ids[chunk_id]
            url = (
                f"https://{self.storage_account}.blob.{self.endpoint}/{container_name}/{path}?comp=block"
                f"&blockid={block_id}"
            )
            headers = {"Content-Length": str(len(chunk))}
            r = await self._send_request_with_authentication_and_retry(
                "PUT", url, chunk_id, headers=headers, data=chunk
            )
        else:
            # single request
            azure_metadata = self._prepare_file_metadata()
            url = f"https://{self.storage_account}.blob.{self.endpoint}/{container_name}/{path}"
            headers = {
                "x-ms-blob-type": "BlockBlob",
                "Content-Encoding": "utf-8",
            }
            headers.update(azure_metadata)
            r = await self._send_request_with_authentication_and_retry(
                "PUT", url, chunk_id, headers=headers, data=chunk
            )
        r.raise_for_status()  # expect status code 201

    async def _complete_multipart_upload(self) -> None:
        container_name = quote(self.azure_location.container_name)
        path = quote(self.azure_location.path + self.meta.dst_file_name.lstrip("/"))
        url = (
            f"https://{self.storage_account}.blob.{self.endpoint}/{container_name}/{path}?comp"
            f"=blocklist"
        )
        root = ET.Element("BlockList")
        for block_id in self.block_ids:
            part = ET.Element("Latest")
            part.text = block_id
            root.append(part)
        # SNOW-1778088: We need to calculate the MD5 sum of this file for Azure Blob storage
        new_stream = not bool(self.meta.src_stream or self.meta.intermediate_stream)
        fd = (
            self.meta.src_stream
            or self.meta.intermediate_stream
            or open(self.meta.real_src_file_name, "rb")
        )
        try:
            if not new_stream:
                # Reset position in file
                fd.seek(0)
            file_content = fd.read()
        finally:
            if new_stream:
                fd.close()
        headers = {
            "x-ms-blob-content-encoding": "utf-8",
            "x-ms-blob-content-md5": base64.b64encode(
                get_md5_for_integrity(file_content)
            ).decode("utf-8"),
        }
        azure_metadata = self._prepare_file_metadata()
        headers.update(azure_metadata)
        retry_id = "COMPLETE"
        self.retry_count[retry_id] = 0
        r = await self._send_request_with_authentication_and_retry(
            "PUT", url, "COMPLETE", headers=headers, data=ET.tostring(root)
        )
        r.raise_for_status()  # expects status code 201

    async def download_chunk(self, chunk_id: int) -> None:
        container_name = quote(self.azure_location.container_name)
        path = quote(self.azure_location.path + self.meta.src_file_name.lstrip("/"))
        url = f"https://{self.storage_account}.blob.{self.endpoint}/{container_name}/{path}"
        if self.num_of_chunks > 1:
            chunk_size = self.chunk_size
            if chunk_id < self.num_of_chunks - 1:
                _range = f"{chunk_id * chunk_size}-{(chunk_id + 1) * chunk_size - 1}"
            else:
                _range = f"{chunk_id * chunk_size}-"
            headers = {"Range": f"bytes={_range}"}
            r = await self._send_request_with_authentication_and_retry(
                "GET", url, chunk_id, headers=headers
            )  # expect 206
        else:
            # single request
            r = await self._send_request_with_authentication_and_retry(
                "GET", url, chunk_id
            )
        if r.status in (200, 206):
            self.write_downloaded_chunk(chunk_id, await r.read())
        r.raise_for_status()
