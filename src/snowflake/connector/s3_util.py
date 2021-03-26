#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import base64
import hashlib
import hmac
import os
from collections import namedtuple
from datetime import datetime
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union
from xml.etree import ElementTree

import OpenSSL

from .constants import HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_VALUE_OCTET_STREAM, FileHeader, ResultStatus
from .encryption_util import EncryptionMetadata
from .errors import S3RestCallFailedError
from .vendored import requests

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

logger = getLogger(__name__)

META_PREFIX = "x-amz-meta-"
SFC_DIGEST = 'sfc-digest'

AMZ_MATDESC = 'x-amz-matdesc'
AMZ_KEY = 'x-amz-key'
AMZ_IV = 'x-amz-iv'

ERRORNO_WSAECONNABORTED = 10053  # network connection was aborted

EXPIRED_TOKEN = 'ExpiredToken'
ADDRESSING_STYLE = 'virtual'  # explicit force to use virtual addressing style

"""
S3 Location: S3 bucket name + path
"""
S3Location = namedtuple(
    "S3Location", [
        "bucket_name",  # S3 bucket name
        "s3path"  # S3 path name

    ])


# TODO retry and concurrent
class SnowflakeS3RestClient:

    def __init__(self, stage_info, use_accelerate_endpoint=False):
        """Rest client for S3 storage.

        Args:
            stage_info:
            use_accelerate_endpoint:
        """
        # Signature version V4
        # Addressing style Virtual Host
        self.stage_info: Dict[str, Any] = stage_info
        stage_credentials = stage_info['creds']
        self.region_name: str = stage_info['region']
        self.aws_access_key_id = stage_credentials['AWS_KEY_ID']
        self.aws_secret_access_key = stage_credentials['AWS_SECRET_KEY']
        self.aws_security_token = stage_credentials.get('AWS_TOKEN', None)
        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        if stage_info['endPoint']:
            # TODO: test
            self.endpoint = ('https://' + stage_info['endPoint'])
        elif use_accelerate_endpoint:
            self.endpoint = "https://{bucket_name}.s3-accelerate.amazonaws.com"
        else:
            self.endpoint = f"https://{{bucket_name}}.s3.{self.region_name}.amazonaws.com"

    @staticmethod
    def sign(secret_key, msg):
        return base64.encodebytes(
            hmac.new(
                secret_key, msg, hashlib.sha1
            ).digest()
        ).strip()

    @staticmethod
    def construct_canonicalized_element(bucket_name: str = None, request_uri: str = "", subresource: str = None):
        res = ""
        if bucket_name:
            res += f"/{bucket_name}"
            if request_uri:
                res += '/' + request_uri
        else:
            # for GET operations without a bucket name
            res += '/'
        if subresource:
            raise NotImplementedError
        return res

    @staticmethod
    def construct_canonicalized_headers(headers: Dict[str, Union[str, List[str]]]) -> str:
        _res = sorted([[k.lower(), v] for k, v in headers.items()])
        res = []

        for i in range(len(_res)):
            k, v = _res[i]
            # if value is a list, convert to string delimited by comma
            if isinstance(v, list):
                v = ','.join(v)
            # if multiline header, replace withs space
            k = k.replace('\n', ' ')
            res.append(k.rstrip() + ':' + v.lstrip())

        ans = '\n'.join(res)
        if ans:
            ans = ans + '\n'

        return ans

    @staticmethod
    def construct_string_to_sign(verb, canonicalized_element, canonicalized_headers, amzdate: str, content_md5="",
                                 content_type=""):
        res = verb + "\n" + content_md5 + "\n" + content_type + "\n"
        res += amzdate + "\n" + canonicalized_headers + canonicalized_element
        return res.encode('UTF-8')

    @staticmethod
    def extract_error_from_xml_response(response: str) -> Tuple[str, str]:
        """Extract error code and error message from the S3's error response.

        Expected format:
        https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses

        Args:
            response: Rest error response in XML format

        Returns: A tuple of strings, i.e. (error code, error message)

        """
        if not response or response.isspace():
            return "", ""
        err = ElementTree.fromstring(response)
        return err.find('Code').text, err.find('Message').text

    @staticmethod
    def extract_bucket_name_and_path(stage_location):
        stage_location = os.path.expanduser(stage_location)
        bucket_name = stage_location
        s3path = ''

        # split stage location as bucket name and path
        if '/' in stage_location:
            bucket_name = stage_location[0:stage_location.index('/')]
            s3path = stage_location[stage_location.index('/') + 1:]
            if s3path and not s3path.endswith('/'):
                s3path += '/'

        return S3Location(
            bucket_name=bucket_name,
            s3path=s3path)

    def get_file_header(self,
                        meta: 'SnowflakeFileMeta',
                        filename: str):
        """Gets the remote file's metadata.

        Args:
            meta: Remote file's metadata info.
            filename: Name of remote file.

        Returns:
            The file header, with expected properties populated or None, based on how the request goes with the
            storage provider.
        """
        s3location = SnowflakeS3RestClient.extract_bucket_name_and_path(meta.client_meta.stage_info['location'])
        s3path = s3location.s3path + filename.lstrip('/')

        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')

        url = self.endpoint.format(bucket_name=s3location.bucket_name) + f"/{s3path}"

        _headers = self.construct_canonicalized_headers({'x-amz-security-token': self.aws_security_token})
        _resource = self.construct_canonicalized_element(bucket_name=s3location.bucket_name, request_uri=s3path)
        string_to_sign = self.construct_string_to_sign("HEAD", _resource, _headers, amzdate)
        signature = self.sign(self.aws_secret_access_key.encode('UTF-8'), string_to_sign)

        authorization_header = "AWS" + " " + self.aws_access_key_id + ":" + signature.decode()

        headers = {'Date': amzdate, 'Authorization': authorization_header,
                   'x-amz-security-token': self.aws_security_token}

        # HTTP HEAD request
        r = requests.head(url, headers=headers)
        if r.status_code == 200:
            meta.result_status = ResultStatus.UPLOADED
            metadata = r.headers
            encryption_metadata = EncryptionMetadata(
                key=metadata.get(META_PREFIX + AMZ_KEY),
                iv=metadata.get(META_PREFIX + AMZ_IV),
                matdesc=metadata.get(META_PREFIX + AMZ_MATDESC),
            ) if metadata.get(META_PREFIX + AMZ_KEY) else None

            return FileHeader(
                digest=metadata.get(META_PREFIX + SFC_DIGEST),
                content_length=metadata.get('Content-Length'),
                encryption_metadata=encryption_metadata
            )
        elif r.status_code == 404:
            logger.debug(f'not found. bucket: {s3location.bucket_name}, path: {s3path}')
            meta.result_status = ResultStatus.NOT_FOUND_FILE
            return FileHeader(
                digest=None,
                content_length=None,
                encryption_metadata=None,
            )
        else:
            err_code, err_message = self.extract_error_from_xml_response(r.text)
            if err_code == EXPIRED_TOKEN:
                # TODO: verify this works
                logger.debug("AWS Token expired. Renew and retry")
                meta.result_status = ResultStatus.RENEW_TOKEN
                return None
            elif r.status_code == '400':
                logger.debug(f'Bad request, token needs to be renewed: {err_message}. '
                             f'bucket: {s3location.bucket_name}, path: {s3path}')
                meta.result_status = ResultStatus.RENEW_TOKEN
                return None
            logger.debug(f"Failed to get metadata for {s3location.bucket_name}, {s3path}: {err_message}")
            meta.result_status = ResultStatus.ERROR
            return None

    def upload_file(self,
                    data_file: str,
                    meta: 'SnowflakeFileMeta',
                    encryption_metadata: 'EncryptionMetadata',
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
        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')

        s3_metadata = {
            META_PREFIX + SFC_DIGEST: meta.sha256_digest,
        }
        if encryption_metadata:
            s3_metadata.update({
                META_PREFIX + AMZ_IV: encryption_metadata.iv,
                META_PREFIX + AMZ_KEY: encryption_metadata.key,
                META_PREFIX + AMZ_MATDESC: encryption_metadata.matdesc,
            })
        s3location = SnowflakeS3RestClient.extract_bucket_name_and_path(
            meta.client_meta.stage_info['location'])
        s3path = s3location.s3path + meta.dst_file_name.lstrip('/')

        x_amz_headers = {'x-amz-security-token': self.aws_security_token}
        x_amz_headers.update(s3_metadata)

        _headers = SnowflakeS3RestClient.construct_canonicalized_headers(x_amz_headers)
        _resource = SnowflakeS3RestClient.construct_canonicalized_element(bucket_name=s3location.bucket_name,
                                                                          request_uri=s3path)

        string_to_sign = SnowflakeS3RestClient.construct_string_to_sign("PUT", _resource, _headers, amzdate,
                                                                        content_type=HTTP_HEADER_VALUE_OCTET_STREAM)
        signature = SnowflakeS3RestClient.sign(self.aws_secret_access_key.encode('UTF-8'), string_to_sign)

        authorization_header = "AWS" + " " + self.aws_access_key_id + ":" + signature.decode()
        x_amz_headers.update({'Date': amzdate, 'Authorization': authorization_header,
                              HTTP_HEADER_CONTENT_TYPE: HTTP_HEADER_VALUE_OCTET_STREAM})

        end_point = f"https://{s3location.bucket_name}.s3.{self.region_name}.amazonaws.com/{s3path}"

        if meta.src_stream is None:
            fd = open(data_file, 'rb')
        else:
            fd = meta.real_src_stream or meta.src_stream
            fd.seek(0)

        try:
            r = requests.put(end_point, data=fd.read(), headers=x_amz_headers)
            if r.status_code == 200:
                logger.debug('DONE putting a file')
                meta.dst_file_size = meta.upload_size
                meta.result_status = ResultStatus.UPLOADED
            else:
                err_code, err_message = self.extract_error_from_xml_response(r.text)
                if err_code == EXPIRED_TOKEN:
                    logger.debug("AWS Token expired. Renew and retry")
                    meta.result_status = ResultStatus.RENEW_TOKEN
                    return
                logger.debug(f"Failed to upload a file: {data_file}, err: {err_code} {err_message}")
                raise S3RestCallFailedError
        except OpenSSL.SSL.SysCallError as err:
            meta.last_error = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it
                meta.result_status = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta.result_status = ResultStatus.NEED_RETRY

    def _download_chunk(self, headers, range):
        # TODO
        pass

    def _native_download_file(self,
                              meta,
                              full_dst_file_name,
                              max_concurrency):
        s3location = self.extract_bucket_name_and_path(meta.client_meta.stage_info['location'])
        s3path = s3location.s3path + meta.src_file_name.lstrip('/')

        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')

        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        url = self.endpoint.format(bucket_name=s3location.bucket_name) + f"/{s3path}"

        _headers = self.construct_canonicalized_headers(
            {'x-amz-security-token': self.aws_security_token})
        _resource = self.construct_canonicalized_element(bucket_name=s3location.bucket_name, request_uri=s3path)
        string_to_sign = self.construct_string_to_sign("GET", _resource, _headers, amzdate)
        signature = self.sign(self.aws_secret_access_key.encode('UTF-8'), string_to_sign)

        authorization_header = "AWS" + " " + self.aws_access_key_id + ":" + signature.decode()

        headers = {'Date': amzdate, 'Authorization': authorization_header,
                   'x-amz-security-token': self.aws_security_token}

        # ************* SEND THE REQUEST *************
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                with open(full_dst_file_name, 'wb+') as fd:
                    fd.write(r.content)
                meta.result_status = ResultStatus.DOWNLOADED
            else:
                err_code, err_message = self.extract_error_from_xml_response(r.text)
                if err_code == EXPIRED_TOKEN:
                    meta.result_status = ResultStatus.RENEW_TOKEN
                else:
                    logger.debug(f"Failed to download a file: {full_dst_file_name}, err: {err_code} {err_message}")
                    raise S3RestCallFailedError
        except OpenSSL.SSL.SysCallError as err:
            meta.last_error = err
            if err.args[0] == ERRORNO_WSAECONNABORTED:
                # connection was disconnected by S3
                # because of too many connections. retry with
                # less concurrency to mitigate it
                meta.result_status = ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY
            else:
                meta.result_status = ResultStatus.NEED_RETRY

    def transfer_accelerate_config(self) -> bool:

        s3location = SnowflakeS3RestClient.extract_bucket_name_and_path(
            self.stage_info['location']
        )

        t = datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')

        # if GS sends us an endpoint, it's likely for FIPS. Use it.
        url = self.endpoint.format(bucket_name=s3location.bucket_name)

        _headers = self.construct_canonicalized_headers({'x-amz-security-token': self.aws_security_token})
        _resource = self.construct_canonicalized_element(bucket_name=s3location.bucket_name, request_uri="?accelerate")
        string_to_sign = SnowflakeS3RestClient.construct_string_to_sign("GET", _resource, _headers, amzdate)
        signature = SnowflakeS3RestClient.sign(self.aws_secret_access_key.encode('UTF-8'), string_to_sign)

        authorization_header = "AWS" + " " + self.aws_access_key_id + ":" + signature.decode()

        headers = {'Date': amzdate, 'Authorization': authorization_header,
                   'x-amz-security-token': self.aws_security_token}

        r = requests.get(url + '/?accelerate', headers=headers)
        if r.status_code == 200:
            config = ElementTree.fromstring(r.text)
            use_accelerate_endpoint = config.find('Status') and config.find('Status').text == 'Enabled'
            logger.debug(f'use_accelerate_endpoint: {use_accelerate_endpoint}')
            return use_accelerate_endpoint
        else:
            err_code, err_message = SnowflakeS3RestClient.extract_error_from_xml_response(r.text)
            if err_code == 'AccessDenied':
                logger.debug(f"Cannot GET bucket accelerate configuration: {err_message}")
            else:
                logger.debug(f"Unknown error when GET bucket accelerate configuration, {err_code}, {err_message}")
            return False
