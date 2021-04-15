#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import base64
import hashlib
import hmac
import os
import time
import xml.etree.cElementTree as ET
from collections import namedtuple
from datetime import datetime
from logging import getLogger
from math import ceil
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union

import OpenSSL
from requests.exceptions import ConnectionError, Timeout

from .constants import (
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_VALUE_OCTET_STREAM,
    FileHeader,
    ResultStatus,
)
from .encryption_util import EncryptionMetadata
from .remote_storage_client import SnowflakeRemoteStorageClient
from .vendored import requests

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

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
RETRY_ON_ERRORS = [429, 500, 502, 503, 504]
SLEEP_MAX = float("inf")
METHODS = {
    "GET": requests.get,
    "PUT": requests.put,
    "POST": requests.post,
    "HEAD": requests.head,
    "DELETE": requests.delete,
}

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", ["bucket_name", "s3path"]  # S3 bucket name  # S3 path name
)


class SnowflakeS3RestClient(SnowflakeRemoteStorageClient):
    def __init__(self, pool, credentials, stage_info, use_accelerate_endpoint=False):
        """Rest client for S3 storage.

        Args:
            stage_info:
            use_accelerate_endpoint:
        """
        super().__init__(pool, credentials)
        # Signature version V4
        # Addressing style Virtual Host
        self.stage_info: Dict[str, Any] = stage_info
        self.region_name: str = stage_info["region"]
        # Chunking
        self.chunks = []
        # Multipart upload only
        self.upload_id = None
        self.etags = None
        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        if stage_info["endPoint"]:
            # TODO: test
            self.endpoint = "https://" + stage_info["endPoint"]
        elif use_accelerate_endpoint:
            self.endpoint = "https://{bucket_name}.s3-accelerate.amazonaws.com"
        else:
            self.endpoint = "https://{bucket_name}.s3.{region_name}.amazonaws.com"

    @staticmethod
    def sign(secret_key, msg):
        return base64.encodebytes(
            hmac.new(secret_key, msg, hashlib.sha1).digest()
        ).strip()

    @staticmethod
    def construct_canonicalized_element(
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
    def construct_string_to_sign(
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
    def _extract_error_from_xml_response(response: str) -> Tuple[str, str]:
        """Extract error code and error message from the S3's error response.

        Expected format:
        https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses

        Args:
            response: Rest error response in XML format

        Returns: A tuple of strings, i.e. (error code, error message)

        """
        if not response or response.isspace():
            return "", ""
        err = ET.fromstring(response)
        return err.find("Code").text, err.find("Message").text

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

    def _get_file_header(self, meta: "SnowflakeFileMeta", filename: str):
        """Gets the remote file's metadata.

        Args:
            meta: Remote file's metadata info.
            filename: Name of remote file.

        Returns:
            The file header, with expected properties populated or None, based on how the request goes with the
            storage provider.
        """

        s3location = self._extract_bucket_name_and_path(self.stage_info["location"])
        s3path = s3location.s3path + filename.lstrip("/")

        url = (
            self.endpoint.format(
                bucket_name=s3location.bucket_name, region_name=self.region_name
            )
            + f"/{s3path}"
        )

        _resource = self.construct_canonicalized_element(
            bucket_name=s3location.bucket_name, request_uri=s3path
        )

        response, status = self._send_request_with_retry(
            url, "HEAD", _resource, acceptable_response=(200, 404)
        )

        if response.status_code == 200:
            meta.result_status = ResultStatus.UPLOADED
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
            logger.debug(f"not found. bucket: {s3location.bucket_name}, path: {s3path}")
            meta.result_status = ResultStatus.NOT_FOUND_FILE
            return FileHeader(
                digest=None,
                content_length=None,
                encryption_metadata=None,
            )

    def _native_upload_file(
        self,
        data_file: str,
        meta: "SnowflakeFileMeta",
        encryption_metadata: "EncryptionMetadata",
        max_concurrency: int,
        multipart_threshold: int,
    ):
        """Uploads the local file to S3.

        Args:
            data_file: File path on local system.
            meta: The File meta object (contains credentials and remote location).
            encryption_metadata: Encryption metadata to be set on object.
            max_concurrency: The maximum number of threads to used to upload.
            multipart_threshold: The number of bytes after which size a file should be uploaded concurrently in chunks.

        Raises:
            HTTPError if some http errors occurred.

        Returns:
            None.
        """
        s3location = SnowflakeS3RestClient._extract_bucket_name_and_path(
            meta.client_meta.stage_info["location"]
        )
        s3path = s3location.s3path + meta.dst_file_name.lstrip("/")
        url = (
            self.endpoint.format(
                bucket_name=s3location.bucket_name, region_name=self.region_name
            )
            + f"/{s3path}"
        )
        s3_metadata = {
            META_PREFIX + SFC_DIGEST: meta.sha256_digest,
        }
        if encryption_metadata:
            s3_metadata.update(
                {
                    META_PREFIX + AMZ_IV: encryption_metadata.iv,
                    META_PREFIX + AMZ_KEY: encryption_metadata.key,
                    META_PREFIX + AMZ_MATDESC: encryption_metadata.matdesc,
                }
            )

        if meta.src_stream is None:
            fd = open(data_file, "rb")
        else:
            fd = meta.real_src_stream or meta.src_stream
            fd.seek(0)

        if meta.upload_size > multipart_threshold:
            num_of_chunks = ceil(meta.upload_size / multipart_threshold)
            chunk_size = multipart_threshold
            if self.upload_id is None:
                # initiate multipart upload
                _resource = self.construct_canonicalized_element(
                    bucket_name=s3location.bucket_name,
                    request_uri=s3path,
                    subresource={"uploads": None},
                )
                response, status = self._send_request_with_retry(
                    url + "?uploads",
                    "POST",
                    _resource,
                    x_amz_headers=s3_metadata,
                    content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
                    headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
                )
                if status != ResultStatus.SUCCEEDED:
                    meta.result_status = status
                    return
                self.upload_id = ET.fromstring(response.content)[2].text
                self.etags = [None] * num_of_chunks
                for _ in range(num_of_chunks):
                    self.chunks.append(fd.read(chunk_size))
            part_ids_to_upload = [
                idx + 1 for idx in range(num_of_chunks) if self.etags[idx] is None
            ]

            def _upload_chunk(part_id: int):
                print(f"_upload_chunk is reached with part id {part_id}")
                chunk_url = url + f"?partNumber={part_id}&uploadId={self.upload_id}"
                query_params = {"partNumber": part_id, "uploadId": self.upload_id}
                chunk_resource = self.construct_canonicalized_element(
                    bucket_name=s3location.bucket_name,
                    request_uri=s3path,
                    subresource=query_params,
                )
                return self._send_request_with_retry(
                    chunk_url, "PUT", chunk_resource, data=self.chunks[part_id - 1]
                )

            results = self.pool.map(_upload_chunk, part_ids_to_upload)
            failed_chunk_transfer = 0
            for idx, (response, status) in enumerate(results):
                if status == ResultStatus.SUCCEEDED:
                    self.chunks[part_ids_to_upload[idx] - 1] = None
                    self.etags[part_ids_to_upload[idx] - 1] = response.headers["ETag"]
                else:
                    meta.result_status = status
                    failed_chunk_transfer += 1
            if failed_chunk_transfer == 0:
                # Complete multipart upload
                _resource = self.construct_canonicalized_element(
                    bucket_name=s3location.bucket_name,
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
                response, status = self._send_request_with_retry(
                    url + f"?uploadId={self.upload_id}",
                    "POST",
                    _resource,
                    data=ET.tostring(root),
                )
                if status == ResultStatus.SUCCEEDED:
                    print(response.content)
                    print("done putting a file")
                logger.debug("DONE putting a file")
                meta.dst_file_size = meta.upload_size
                meta.result_status = ResultStatus.UPLOADED
        else:
            _resource = SnowflakeS3RestClient.construct_canonicalized_element(
                bucket_name=s3location.bucket_name, request_uri=s3path
            )
            response, status = self._send_request_with_retry(
                url,
                "PUT",
                _resource,
                data=fd.read(),
                x_amz_headers=s3_metadata,
                headers={HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM},
                content_type=HTTP_HEADER_VALUE_OCTET_STREAM,
            )
            if status == ResultStatus.SUCCEEDED:
                logger.debug("DONE putting a file")
                meta.dst_file_size = meta.upload_size
                meta.result_status = ResultStatus.UPLOADED
            else:
                meta.result_status = status

    def _abort_multipart_upload(self, meta: "SnowflakeFileMeta"):
        if self.upload_id is None:
            return
        s3location = SnowflakeS3RestClient._extract_bucket_name_and_path(
            meta.client_meta.stage_info["location"]
        )
        s3path = s3location.s3path + meta.dst_file_name.lstrip("/")
        url = (
            self.endpoint.format(
                bucket_name=s3location.bucket_name, region_name=self.region_name
            )
            + f"/{s3path}"
            + f"?uploadId={self.upload_id}"
        )
        _resource = self.construct_canonicalized_element(
            bucket_name=s3location.bucket_name,
            request_uri=s3path,
            subresource={"uploadId": self.upload_id},
        )
        try:
            response, status = self._send_request_with_retry(url, "DELETE", _resource)
            if status == ResultStatus.SUCCEEDED:
                logger.debug(
                    f"Successfully aborting the multipart upload {self.upload_id}."
                )
            else:
                logger.debug(f"Aborting multipart upload {self.upload_id} failed.")
        except Exception as e:
            logger.debug(
                f"Aborting multipart upload {self.upload_id} failed due to {e}."
            )

    def _send_request_with_retry(
        self,
        url: str,
        verb: str,
        resources: str,
        x_amz_headers: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        content_type: str = "",
        data: bytes = None,
        acceptable_response: Tuple[int] = (200,),
    ) -> Tuple[Union[requests.Response, None], ResultStatus]:
        if not x_amz_headers:
            x_amz_headers = {}
        if not headers:
            headers = {}
        rest_call = METHODS[verb]
        retry_count = 0
        while retry_count < MAXIMUM_RETRY:
            t = datetime.utcnow()
            amzdate = t.strftime("%Y%m%dT%H%M%SZ")
            cur_timestamp = self.credentials.timestamp

            if "AWS_TOKEN" in self.credentials.creds:
                x_amz_headers["x-amz-security-token"] = self.credentials.creds.get(
                    "AWS_TOKEN"
                )

            _x_amz_headers = self.construct_canonicalized_headers(x_amz_headers)
            string_to_sign = self.construct_string_to_sign(
                verb, resources, _x_amz_headers, amzdate, content_type=content_type
            )
            signature = self.sign(
                self.credentials.creds["AWS_SECRET_KEY"].encode("UTF-8"), string_to_sign
            )
            authorization_header = (
                "AWS"
                + " "
                + self.credentials.creds["AWS_KEY_ID"]
                + ":"
                + signature.decode()
            )
            headers.update(x_amz_headers)
            headers["Date"] = amzdate
            headers["Authorization"] = authorization_header

            rest_args = {"headers": headers}
            if data:
                rest_args["data"] = data

            try:
                r = rest_call(url, **rest_args)
                if r.status_code in acceptable_response:
                    return r, ResultStatus.SUCCEEDED
                elif r.status_code in RETRY_ON_ERRORS:
                    time.sleep(min((2 ** retry_count) * 100, SLEEP_MAX))
                    retry_count += 1
                    continue
                else:
                    err_code, err_message = self._extract_error_from_xml_response(
                        r.text
                    )
                    if err_code == EXPIRED_TOKEN:
                        if cur_timestamp == self.credentials.timestamp:
                            self.credentials.update(cur_timestamp)
                            continue
                    else:
                        return r, ResultStatus.ERROR
            except OpenSSL.SSL.SysCallError as err:
                if err.args[0] == ERRORNO_WSAECONNABORTED:
                    logger.debug(
                        "connection disconnected by S3 due to too many concurrent connections, retrying with "
                        "less concurrency"
                    )
                    return None, ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
                else:
                    time.sleep(min((2 ** retry_count) * 100, SLEEP_MAX))
                    retry_count += 1
                    continue
            except (Timeout, ConnectionError):
                time.sleep(min((2 ** retry_count) * 100, SLEEP_MAX))
                retry_count += 1
                continue
        return None, ResultStatus.NEED_RETRY

    def _native_download_file(self, meta, full_dst_file_name, max_concurrency):
        s3location = self._extract_bucket_name_and_path(
            meta.client_meta.stage_info["location"]
        )
        s3path = s3location.s3path + meta.src_file_name.lstrip("/")
        url = (
            self.endpoint.format(
                bucket_name=s3location.bucket_name, region_name=self.region_name
            )
            + f"/{s3path}"
        )
        _resource = self.construct_canonicalized_element(
            bucket_name=s3location.bucket_name, request_uri=s3path
        )
        meta.result_status = None
        if meta.src_file_size > meta.multipart_threshold:
            chunk_size = meta.multipart_threshold
            num_of_chunks = ceil(meta.src_file_size / meta.multipart_threshold)
            if not self.chunks:
                self.chunks = [None] * num_of_chunks

            def _download_chunk(_range: str):
                return self._send_request_with_retry(
                    url, "GET", _resource, headers={"Range": _range}
                )

            empty_chunks_idx = [
                idx for idx in range(num_of_chunks) if self.chunks[idx] is None
            ]
            ranges = [
                f"{idx * chunk_size}-{min((idx + 1) * chunk_size, meta.src_file_size) - 1}"
                for idx in empty_chunks_idx
            ]
            results = self.pool.map(_download_chunk, ranges)
            failed_chunk_transfer = 0
            for idx, (response, status) in enumerate(results):
                if status == ResultStatus.SUCCEEDED:
                    self.chunks[empty_chunks_idx[idx]] = response.content
                else:
                    failed_chunk_transfer += 1
                    meta.result_status = status
            # write to directory if all chunks downloaded
            if failed_chunk_transfer == 0:
                with open(full_dst_file_name, "wb+") as fd:
                    for chunk in self.chunks:
                        fd.write(chunk)
                meta.result_status = ResultStatus.DOWNLOADED
        else:
            response, status = self._send_request_with_retry(url, "GET", _resource)
            if status == ResultStatus.SUCCEEDED:
                with open(full_dst_file_name, "wb+") as fd:
                    fd.write(response.content)
                meta.result_status = ResultStatus.DOWNLOADED
            else:
                meta.result_status = status

    def transfer_accelerate_config(self) -> bool:

        s3location = SnowflakeS3RestClient._extract_bucket_name_and_path(
            self.stage_info["location"]
        )
        url = (
            self.endpoint.format(
                bucket_name=s3location.bucket_name, region_name=self.region_name
            )
            + "/?accelerate"
        )
        _resource = self.construct_canonicalized_element(
            bucket_name=s3location.bucket_name, subresource={"accelerate": None}
        )

        response, status = self._send_request_with_retry(
            url, "GET", _resource, acceptable_response=(200, 403)
        )
        if response.status_code == 200:
            config = ET.fromstring(response.text)
            use_accelerate_endpoint = (
                config.find("Status") and config.find("Status").text == "Enabled"
            )
            logger.debug(f"use_accelerate_endpoint: {use_accelerate_endpoint}")
            return use_accelerate_endpoint
        return False
