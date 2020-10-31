#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging
from unittest import mock

import pytest
import requests
from requests import Response

from snowflake.connector.constants import ResultStatus

from ..randomize import random_string

pytestmark = pytest.mark.gcp

try:
    from snowflake.connector.gcs_util import SnowflakeGCSUtil  # NOQA
except ImportError:
    SnowflakeGCSUtil = None


def test_create_client(caplog):
    """Creates a GCSUtil with an access token."""
    client = SnowflakeGCSUtil.create_client({'creds': {'GCS_ACCESS_TOKEN': 'fake_token'}})
    assert client is None
    assert all([log in caplog.record_tuples for log in [
        ('snowflake.connector.gcs_util', logging.DEBUG, "len(GCS_ACCESS_TOKEN): 10"),
        ('snowflake.connector.gcs_util', logging.DEBUG, "GCS operations with an access token are currently unsupported")
    ]])


def test_native_download_access_token(caplog):
    """Tests that GCS access token error is correctly logged when downloading."""
    meta = {}
    SnowflakeGCSUtil._native_download_file(meta, None, 99)
    assert meta['result_status'] == ResultStatus.ERROR
    assert (('snowflake.connector.gcs_util', logging.ERROR, "GCS download operation with an access token is "
                                                            "currently unsupported") in caplog.record_tuples)


def test_native_upload_access_token(caplog):
    """Tests that GCS access token error is correctly logged when uploading."""
    meta = {}
    SnowflakeGCSUtil.upload_file(None, meta, None, 99)
    assert meta['result_status'] == ResultStatus.ERROR
    assert (('snowflake.connector.gcs_util', logging.ERROR, "GCS upload operation with an access token is "
                                                            "currently unsupported") in caplog.record_tuples)


@pytest.mark.parametrize('errno', [403, 408, 429, 500, 503])
def test_upload_retry_errors(errno, tmpdir):
    """Tests whether retryable errors are handled correctly when upploading."""
    f_name = str(tmpdir.join('some_file.txt'))
    resp = Response()
    resp.status_code = errno
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with open(f_name, 'w') as f:
        f.write(random_string(15))
    with mock.patch('requests.put', side_effect=requests.exceptions.HTTPError(response=resp)):
        SnowflakeGCSUtil.upload_file(f_name, meta, None, 99)
        assert isinstance(meta['last_error'], requests.exceptions.HTTPError)
        assert meta['result_status'] == ResultStatus.NEED_RETRY


def test_upload_uncaught_exception(tmpdir):
    """Tests whether non-retryable errors are handled correctly when uploading."""
    f_name = str(tmpdir.join('some_file.txt'))
    resp = Response()
    resp.status_code = 501
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with open(f_name, 'w') as f:
        f.write(random_string(15))
    with mock.patch('requests.put', side_effect=requests.exceptions.HTTPError(response=resp)):
        with pytest.raises(requests.exceptions.HTTPError):
            SnowflakeGCSUtil.upload_file(f_name, meta, None, 99)


@pytest.mark.parametrize('errno', [403, 408, 429, 500, 503])
def test_download_retry_errors(errno, tmpdir):
    """Tests whether retryable errors are handled correctly when downloading."""
    resp = Response()
    resp.status_code = errno
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with mock.patch('requests.get', side_effect=requests.exceptions.HTTPError(response=resp)):
        SnowflakeGCSUtil._native_download_file(meta, str(tmpdir), 99)
        assert isinstance(meta['last_error'], requests.exceptions.HTTPError)
        assert meta['result_status'] == ResultStatus.NEED_RETRY


def test_download_uncaught_exception(tmpdir):
    """Tests whether non-retryable errors are handled correctly when downloading."""
    resp = Response()
    resp.status_code = 501
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with mock.patch('requests.get', side_effect=requests.exceptions.HTTPError(response=resp)):
        with pytest.raises(requests.exceptions.HTTPError):
            SnowflakeGCSUtil._native_download_file(meta, str(tmpdir), 99)


def test_upload_put_timeout(tmpdir, caplog):
    """Tests whether timeout error is handled correctly when uploading."""
    f_name = str(tmpdir.join('some_file.txt'))
    resp = Response()
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with open(f_name, 'w') as f:
        f.write(random_string(15))
    with mock.patch('requests.put', side_effect=requests.exceptions.Timeout(response=resp)):
        SnowflakeGCSUtil.upload_file(f_name, meta, None, 99)
    assert isinstance(meta['last_error'], requests.exceptions.Timeout)
    assert meta['result_status'] == ResultStatus.NEED_RETRY
    assert all([log in caplog.record_tuples for log in [
        ('snowflake.connector.gcs_util', logging.DEBUG, 'GCS file upload Timeout Error: ')
    ]])


def test_upload_get_timeout(tmpdir, caplog):
    """Tests whether timeout error is handled correctly when downloading."""
    resp = Response()
    meta = {'presigned_url': ['some_url'], 'sha256_digest': 'asd'}
    with mock.patch('requests.get', side_effect=requests.exceptions.Timeout(response=resp)):
        SnowflakeGCSUtil._native_download_file(meta, str(tmpdir), 99)
    assert isinstance(meta['last_error'], requests.exceptions.Timeout)
    assert meta['result_status'] == ResultStatus.NEED_RETRY
    assert ('snowflake.connector.gcs_util', logging.DEBUG, 'GCS file download Timeout Error: ') in caplog.record_tuples


def test_get_file_header_none():
    """Tests whether default file handle created by get_file_header is as expected."""
    file_header = SnowflakeGCSUtil.get_file_header({}, 'file')
    assert file_header.digest is None
    assert file_header.content_length is None
    assert file_header.encryption_metadata is None
