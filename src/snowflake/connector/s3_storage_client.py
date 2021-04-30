#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import base64
import os
import xml.etree.cElementTree as ET
from collections import namedtuple
from datetime import datetime
from io import IOBase
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict, List, Union

import OpenSSL
import requests
from cryptography.hazmat.primitives import hashes, hmac
from requests.exceptions import ConnectionError, Timeout

from .constants import (
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_VALUE_OCTET_STREAM,
    FileHeader,
    ResultStatus,
)
from .encryption_util import EncryptionMetadata
from .storage_client import SnowflakeStorageClient

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta, StorageCredential

logger = getLogger(__name__)

META_PREFIX = "x-amz-meta-"
SFC_DIGEST = "sfc-digest"

AMZ_MATDESC = "x-amz-matdesc"
AMZ_KEY = "x-amz-key"
AMZ_IV = "x-amz-iv"

ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

EXPIRED_TOKEN = "ExpiredToken"
ADDRESSING_STYLE = "virtual"  # explicit force to use virtual addressing style
MAXIMUM_RETRY = 3
TRANSIENT_HTTP_CODE = (408, 429, 500, 502, 503, 504)
TRANSIENT_ERRORS = (OpenSSL.SSL.SysCallError, Timeout, ConnectionError)
SLEEP_MAX = float("inf")

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", ["bucket_name", "s3path"]  # S3 bucket name  # S3 path name
)


class SnowflakeS3RestClient(SnowflakeStorageClient):
    def __init__(
        self,
        meta: "SnowflakeFileMeta",
        credentials: "StorageCredential",
        stage_info: Dict[str, Any],
        chunk_size: int,
        use_accelerate_endpoint: bool = False,
    ):
        """Rest client for S3 storage.

        Args:
            stage_info:
            use_accelerate_endpoint:
        """
        super().__init__(meta, stage_info, chunk_size, credentials=credentials)
        # Signature version V4
        # Addressing style Virtual Host
        self.region_name: str = stage_info["region"]
        # Multipart upload only
        self.upload_id = None
        self.etags = None
        self.s3location: "S3Location" = (
            SnowflakeS3RestClient._extract_bucket_name_and_path(
                self.stage_info["location"]
            )
        )
        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        if stage_info["endPoint"]:
            self.endpoint = (
                f"https://{self.s3location.bucket_name}." + stage_info["endPoint"]
            )
        elif use_accelerate_endpoint:
            self.endpoint = (
                f"https://{self.s3location.bucket_name}.s3-accelerate.amazonaws.com"
            )
        else:
            self.endpoint = f"https://{self.s3location.bucket_name}.s3.{self.region_name}.amazonaws.com"

    @staticmethod
    def sign(secret_key, msg):
        h = hmac.HMAC(secret_key, hashes.SHA1())
        h.update(msg)
        return base64.encodebytes(h.finalize()).strip()

    @staticmethod
    def _construct_canonicalized_element(
        bucket_name: str = None,
        request_uri: str = "",
        subresource: Dict[str, Union[str, int, None]] = None,
    ):
        if not subresource:
            subresource = {}
        res = ""
        if bucket_name:
            res += f"/{bucket_name}"
            if request_uri:
                res += "/" + request_uri
        else:
            # for GET operations without a bucket name
            res += "/"
        if subresource:
            res += "?"
            keys = sorted(subresource.keys())
            res += (
                keys[0]
                if subresource[keys[0]] is None
                else f"{keys[0]}={subresource[keys[0]]}"
            )
            for k in keys[1:]:
                query_str = k if subresource[k] is None else f"{k}={subresource[k]}"
                res += f"&{query_str}"
        return res

    @staticmethod
    def construct_canonicalized_headers(
        headers: Dict[str, Union[str, List[str]]]
    ) -> str:
        _res = sorted([[k.lower(), v] for k, v in headers.items()])
        res = []

        for i in range(len(_res)):
            k, v = _res[i]
            # if value is a list, convert to string delimited by comma
            if isinstance(v, list):
                v = ",".join(v)
            # if multiline header, replace withs space
            k = k.replace("\n", " ")
            res.append(k.rstrip() + ":" + v.lstrip())

        ans = "\n".join(res)
        if ans:
            ans = ans + "\n"

        return ans

    @staticmethod
    def _construct_string_to_sign(
        verb,
        canonicalized_element,
        canonicalized_headers,
        amzdate: str,
        content_md5="",
        content_type="",
    ):
        res = verb + "\n" + content_md5 + "\n" + content_type + "\n"
        res += amzdate + "\n" + canonicalized_headers + canonicalized_element
        return res.encode("UTF-8")

    @staticmethod
    def _has_expired_token(response: requests.Response) -> bool:
        """Extract error code and error message from the S3's error response.

        Expected format:
        https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses

        Args:
            response: Rest error response in XML format

        Returns: True if the error response is caused by token expiration

        """
        if response.status_code != 400:
            return False
        message = response.text
        if not message or message.isspace():
            return False
        err = ET.fromstring(message)
        return err.find("Code").text == EXPIRED_TOKEN

    @staticmethod
    def _extract_bucket_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        bucket_name = stage_location
        s3path = ""

        # split stage location as bucket name and path
        if "/" in stage_location:
            bucket_name = stage_location[0 : stage_location.index("/")]
            s3path = stage_location[stage_location.index("/") + 1 :]
            if s3path and not s3path.endswith("/"):
                s3path += "/"

        return S3Location(bucket_name=bucket_name, s3path=s3path)

    def _send_request_with_authentication_and_retry(
        self,
        url: str,
        verb: str,
        resources: str,
        retry_id: Union[int, str],
        x_amz_headers: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        content_type: str = "",
        data: Union[bytes, bytearray, IOBase] = None,
    ) -> requests.Response:
        if not x_amz_headers:
            x_amz_headers = {}
        if not headers:
            headers = {}

        def generate_authenticated_url_and_args():
            t = datetime.utcnow()
            amzdate = t.strftime("%Y%m%dT%H%M%SZ")

            if "AWS_TOKEN" in self.credentials.creds:
                x_amz_headers["x-amz-security-token"] = self.credentials.creds.get(
                    "AWS_TOKEN"
                )
            _x_amz_headers = self.construct_canonicalized_headers(x_amz_headers)
            string_to_sign = self._construct_string_to_sign(
                verb, resources, _x_amz_headers, amzdate, content_type=content_type
            )
            signature = self.sign(
                self.credentials.creds["AWS_SECRET_KEY"].encode("UTF-8"), string_to_sign
            )
            authorization_header = (  # TODO
                "AWS " + self.credentials.creds["AWS_KEY_ID"] + ":" + signature.decode()
            )
            headers.update(x_amz_headers)
            headers["Date"] = amzdate
            headers["Authorization"] = authorization_header
            rest_args = {"headers": headers}

            if data:
                rest_args["data"] = data

            return url, rest_args

        return self._send_request_with_retry(
            verb, generate_authenticated_url_and_args, retry_id
        )

    def get_file_header(self, filename: str) -> Union[FileHeader, None]:
        """Gets the metadata of file in specified location.

        Args:
            filename: Name of remote file.

        Returns:
            None if HEAD returns 404, otherwise a FileHeader instance populated with metadata
        """
        s3path = self.s3location.s3path + filename.lstrip("/")
        url = self.endpoint + f"/{s3path}"

        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name, request_uri=s3path
        )
        retry_id = "HEAD"
        self.retry_count[retry_id] = 0
        response = self._send_request_with_authentication_and_retry(
            url, "HEAD", _resource, retry_id
        )
        if response.status_code == 200:
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
        elif response.status_code == 404:
            logger.debug(
                f"not found. bucket: {self.s3location.bucket_name}, path: {s3path}"
            )
            self.meta.result_status = ResultStatus.NOT_FOUND_FILE
            return None
        else:
            response.raise_for_status()

    def _prepare_file_metadata(self) -> Dict[str, Any]:
        """Construct metadata for a file to be uploaded.

        Returns: File metadata in a dict.

        """
        s3_metadata = {
            META_PREFIX + SFC_DIGEST: self.meta.sha256_digest,
        }
        if self.encryption_metadata:
            s3_metadata.update(
                {
                    META_PREFIX + AMZ_IV: self.encryption_metadata.iv,
                    META_PREFIX + AMZ_KEY: self.encryption_metadata.key,
                    META_PREFIX + AMZ_MATDESC: self.encryption_metadata.matdesc,
                }
            )
        return s3_metadata

    def _initiate_multipart_upload(self):
        s3path = self.s3location.s3path + self.meta.dst_file_name.lstrip("/")
        url = self.endpoint + f"/{s3path}?uploads"
        s3_metadata = self._prepare_file_metadata()
        # initiate multipart upload
        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name,
            request_uri=s3path,
            subresource={"uploads": None},
        )
        retry_id = "Initiate"
        self.retry_count[retry_id] = 0
        response = self._send_request_with_authentication_and_retry(
            url,
            "POST",
            _resource,
            retry_id,
            x_amz_headers=s3_metadata,
            content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
            headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
        )
        if response.status_code == 200:
            self.upload_id = ET.fromstring(response.content)[2].text
            self.etags = [None] * self.num_of_chunks
        else:
            response.raise_for_status()

    def _upload_chunk(self, chunk_id: int, chunk: bytes):
        s3path = self.s3location.s3path + self.meta.dst_file_name.lstrip("/")
        url = self.endpoint + f"/{s3path}"

        if self.num_of_chunks == 1:  # single request
            s3_metadata = self._prepare_file_metadata()
            _resource = self._construct_canonicalized_element(
                bucket_name=self.s3location.bucket_name, request_uri=s3path
            )
            response = self._send_request_with_authentication_and_retry(
                url,
                "PUT",
                _resource,
                chunk_id,
                data=chunk,
                x_amz_headers=s3_metadata,
                headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
                content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
            )
            response.raise_for_status()
        else:
            # multipart PUT
            chunk_url = url + f"?partNumber={chunk_id+1}&uploadId={self.upload_id}"
            query_params = {"partNumber": chunk_id + 1, "uploadId": self.upload_id}
            chunk_resource = self._construct_canonicalized_element(
                bucket_name=self.s3location.bucket_name,
                request_uri=s3path,
                subresource=query_params,
            )
            response = self._send_request_with_authentication_and_retry(
                chunk_url, "PUT", chunk_resource, chunk_id, data=chunk
            )
            if response.status_code == 200:
                self.etags[chunk_id] = response.headers["ETag"]
            response.raise_for_status()

    def _complete_multipart_upload(self):
        s3path = self.s3location.s3path + self.meta.dst_file_name.lstrip("/")
        url = self.endpoint + f"/{s3path}?uploadId={self.upload_id}"
        logger.debug("Initiating multipart upload complete")
        # Complete multipart upload
        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name,
            request_uri=s3path,
            subresource={"uploadId": self.upload_id},
        )
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
        response = self._send_request_with_authentication_and_retry(
            url,
            "POST",
            _resource,
            retry_id,
            data=ET.tostring(root),
        )
        response.raise_for_status()

    def _abort_multipart_upload(self):
        if self.upload_id is None:
            return
        s3path = self.s3location.s3path + self.meta.dst_file_name.lstrip("/")
        url = self.endpoint + f"/{s3path}?uploadId={self.upload_id}"

        retry_id = "Abort"
        self.retry_count[retry_id] = 0
        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name,
            request_uri=s3path,
            subresource={"uploadId": self.upload_id},
        )
        response = self._send_request_with_authentication_and_retry(
            url, "DELETE", _resource, retry_id
        )
        response.raise_for_status()

    def download_chunk(self, chunk_id: int):
        logger.debug(f"Downloading chunk {chunk_id}")
        s3path = self.s3location.s3path + self.meta.src_file_name.lstrip("/")
        url = self.endpoint + f"/{s3path}"
        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name, request_uri=s3path
        )
        if self.num_of_chunks == 1:
            response = self._send_request_with_authentication_and_retry(
                url, "GET", _resource, chunk_id
            )
            if response.status_code == 200:
                self.chunks[0] = response.content
                self.meta.result_status = ResultStatus.DOWNLOADED
            response.raise_for_status()
        else:
            chunk_size = self.chunk_size
            if chunk_id < self.num_of_chunks - 1:
                _range = f"{chunk_id * chunk_size}-{(chunk_id+1)*chunk_size-1}"
            else:
                _range = f"{chunk_id * chunk_size}-"

            response = self._send_request_with_authentication_and_retry(
                url,
                "GET",
                _resource,
                chunk_id,
                headers={"Range": f"bytes={_range}"},
            )
            if response.status_code in (200, 206):
                self.chunks[chunk_id] = response.content
            response.raise_for_status()

    def transfer_accelerate_config(self) -> bool:
        url = self.endpoint + "/?accelerate"
        _resource = self._construct_canonicalized_element(
            bucket_name=self.s3location.bucket_name, subresource={"accelerate": None}
        )
        retry_id = "accelerate"
        self.retry_count[retry_id] = 0
        response = self._send_request_with_authentication_and_retry(
            url, "GET", _resource, retry_id
        )
        if response.status_code == 200:
            config = ET.fromstring(response.text)
            use_accelerate_endpoint = (
                config.find("Status") and config.find("Status").text == "Enabled"
            )
            logger.debug(f"use_accelerate_endpoint: {use_accelerate_endpoint}")
            return use_accelerate_endpoint
        return False
