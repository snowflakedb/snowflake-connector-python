#!/usr/bin/env python
from __future__ import annotations

import errno
import json
import logging
import os
import time
from unittest.mock import MagicMock, Mock, PropertyMock, patch
from uuid import uuid4

import OpenSSL.SSL
import pytest

import snowflake.connector
from snowflake.connector.compat import (
    BAD_GATEWAY,
    BAD_REQUEST,
    FORBIDDEN,
    GATEWAY_TIMEOUT,
    INTERNAL_SERVER_ERROR,
    OK,
    PERMANENT_REDIRECT,
    SERVICE_UNAVAILABLE,
    TEMPORARY_REDIRECT,
    UNAUTHORIZED,
    BadStatusLine,
    IncompleteRead,
)
from snowflake.connector.errors import (
    DatabaseError,
    Error,
    ForbiddenError,
    HttpError,
    OperationalError,
    OtherHTTPRetryableError,
    ServiceUnavailableError,
)
from snowflake.connector.network import (
    STATUS_TO_EXCEPTION,
    RetryRequest,
    SnowflakeRestful,
    is_retryable_http_code,
)

from .mock_utils import (
    get_mock_session_manager,
    mock_connection,
    mock_request_with_action,
    zero_backoff,
)

# We need these for our OldDriver tests. We run most up to date tests with the oldest supported driver version
try:
    import snowflake.connector.vendored.urllib3.contrib.pyopenssl
    from snowflake.connector.vendored import requests, urllib3
    from snowflake.connector.vendored.requests.exceptions import SSLError
except ImportError:  # pragma: no cover
    import requests
    import urllib3
    from requests.exceptions import SSLError

THIS_DIR = os.path.dirname(os.path.realpath(__file__))


class Cnt:
    def __init__(self):
        self.c = 0

    def set(self, cnt):
        self.c = cnt

    def reset(self):
        self.set(0)


def fake_connector() -> snowflake.connector.SnowflakeConnection:
    return snowflake.connector.connect(
        user="user",
        account="account",
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
    )


@patch("snowflake.connector.network.SnowflakeRestful._request_exec")
def test_retry_reason(mockRequestExec):
    url = ""
    cnt = Cnt()

    def mock_exec(session, method, full_url, headers, data, token, **kwargs):
        # take actions based on data["sqlText"]
        nonlocal url
        url = full_url
        data = json.loads(data)
        sql = data.get("sqlText", "default")
        success_result = {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
                "idToken": None,
                "parameters": [{"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}],
            },
        }
        cnt.c += 1
        if "retry" in sql:
            # error = HTTP Error 429
            if cnt.c < 3:  # retry twice for 429 error
                raise RetryRequest(OtherHTTPRetryableError(errno=429))
            return success_result
        elif "unknown error" in sql:
            # Raise unknown http error
            if cnt.c == 1:  # retry once for 100 error
                raise RetryRequest(OtherHTTPRetryableError(errno=100))
            return success_result
        elif "flip" in sql:
            if cnt.c == 1:  # retry first with 100
                raise RetryRequest(OtherHTTPRetryableError(errno=100))
            elif cnt.c == 2:  # then with 429
                raise RetryRequest(OtherHTTPRetryableError(errno=429))
            return success_result

        return success_result

    conn = fake_connector()
    mockRequestExec.side_effect = mock_exec

    # ensure query requests don't have the retryReason if retryCount == 0
    cnt.reset()
    conn.cmd_query("success", 0, uuid4())
    assert "retryReason" not in url
    assert "retryCount" not in url

    # ensure query requests have correct retryReason when retry reason is sent by server
    cnt.reset()
    conn.cmd_query("retry", 0, uuid4())
    assert "retryReason=429" in url
    assert "retryCount=2" in url

    cnt.reset()
    conn.cmd_query("unknown error", 0, uuid4())
    assert "retryReason=100" in url
    assert "retryCount=1" in url

    # ensure query requests have retryReason reset to 0 when no reason is given
    cnt.reset()
    conn.cmd_query("success", 0, uuid4())
    assert "retryReason" not in url
    assert "retryCount" not in url

    # ensure query requests have retryReason gets updated with updated error code
    cnt.reset()
    conn.cmd_query("flip", 0, uuid4())
    assert "retryReason=429" in url
    assert "retryCount=2" in url

    # ensure that disabling works and only suppresses retryReason
    conn._enable_retry_reason_in_query_response = False

    cnt.reset()
    conn.cmd_query("retry", 0, uuid4())
    assert "retryReason" not in url
    assert "retryCount=2" in url

    cnt.reset()
    conn.cmd_query("unknown error", 0, uuid4())
    assert "retryReason" not in url
    assert "retryCount=1" in url


def test_request_exec():
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": '{"code": 12345}',
        "token": None,
    }

    login_parameters = {
        **default_parameters,
        "full_url": "https://bad_id.snowflakecomputing.com:443/session/v1/login-request?request_id=s0m3-r3a11Y-rAnD0m-reqID&request_guid=s0m3-r3a11Y-rAnD0m-reqGUID",
    }

    # request mock
    output_data = {"success": True, "code": 12345}
    request_mock = MagicMock()
    type(request_mock).status_code = PropertyMock(return_value=OK)
    request_mock.json.return_value = output_data

    # session mock
    session = MagicMock()
    session.request.return_value = request_mock

    # success
    ret = rest._request_exec(session=session, **default_parameters)
    assert ret == output_data, "output data"

    # retryable exceptions
    for errcode in [
        BAD_REQUEST,  # 400
        FORBIDDEN,  # 403
        INTERNAL_SERVER_ERROR,  # 500
        BAD_GATEWAY,  # 502
        SERVICE_UNAVAILABLE,  # 503
        GATEWAY_TIMEOUT,  # 504
        555,  # random 5xx error
    ]:
        type(request_mock).status_code = PropertyMock(return_value=errcode)
        try:
            rest._request_exec(session=session, **default_parameters)
            pytest.fail("should fail")
        except RetryRequest as e:
            cls = STATUS_TO_EXCEPTION.get(errcode, OtherHTTPRetryableError)
            assert isinstance(e.args[0], cls), "must be internal error exception"

    # unauthorized
    type(request_mock).status_code = PropertyMock(return_value=UNAUTHORIZED)
    with pytest.raises(HttpError):
        rest._request_exec(session=session, **default_parameters)

    # unauthorized with catch okta unauthorized error
    # TODO: what is the difference to InterfaceError?
    type(request_mock).status_code = PropertyMock(return_value=UNAUTHORIZED)
    with pytest.raises(DatabaseError):
        rest._request_exec(
            session=session, catch_okta_unauthorized_error=True, **default_parameters
        )

    # forbidden on login-request raises ForbiddenError
    type(request_mock).status_code = PropertyMock(return_value=FORBIDDEN)
    with pytest.raises(ForbiddenError):
        rest._request_exec(session=session, **login_parameters)

    class IncompleteReadMock(IncompleteRead):
        def __init__(self):
            IncompleteRead.__init__(self, "")

    # handle retryable exception
    for exc in [
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ReadTimeout,
        IncompleteReadMock,
        urllib3.exceptions.ProtocolError,
        requests.exceptions.ConnectionError,
        AttributeError,
    ]:
        session = MagicMock()
        session.request = Mock(side_effect=exc)

        try:
            rest._request_exec(session=session, **default_parameters)
            pytest.fail("should fail")
        except RetryRequest as e:
            cause = e.args[0]
            assert isinstance(cause, exc), "same error class"

    # handle OpenSSL errors and BadStateLine
    for exc in [
        OpenSSL.SSL.SysCallError(errno.ECONNRESET),
        OpenSSL.SSL.SysCallError(errno.ETIMEDOUT),
        OpenSSL.SSL.SysCallError(errno.EPIPE),
        OpenSSL.SSL.SysCallError(-1),  # unknown
        # TODO: should we keep this?
        # urllib3.exceptions.ReadTimeoutError(None, None, None),
        BadStatusLine("fake"),
    ]:
        session = MagicMock()
        session.request = Mock(side_effect=exc)
        try:
            rest._request_exec(session=session, **default_parameters)
            pytest.fail("should fail")
        except RetryRequest as e:
            assert e.args[0] == exc, "same error instance"


def test_fetch():
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )

    cnt = Cnt()
    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {"cnt": cnt},
        "data": '{"code": 12345}',
    }

    NOT_RETRYABLE = 1000

    class NotRetryableException(Exception):
        pass

    def fake_request_exec(**kwargs):
        headers = kwargs.get("headers")
        cnt = headers["cnt"]
        time.sleep(
            0.1
        )  # Realistic network delay simulation without excessive test slowdown
        if cnt.c <= 1:
            # the first two raises failure
            cnt.c += 1
            raise RetryRequest(Exception("can retry"))
        elif cnt.c == NOT_RETRYABLE:
            # not retryable exception
            raise NotRetryableException("cannot retry")
        else:
            # return success in the third attempt
            return {"success": True, "data": "valid data"}

    # inject a fake method
    rest._request_exec = fake_request_exec

    # first two attempts will fail but third will success
    cnt.reset()
    ret = rest.fetch(timeout=5, **default_parameters)
    assert ret == {"success": True, "data": "valid data"}
    assert not rest._connection.errorhandler.called  # no error

    # first attempt to reach timeout even if the exception is retryable
    cnt.reset()
    ret = rest.fetch(
        timeout=0.001, **default_parameters
    )  # Timeout well before 0.1s sleep completes
    assert ret == {}
    assert rest._connection.errorhandler.called  # error

    # not retryable excpetion
    cnt.set(NOT_RETRYABLE)
    with pytest.raises(NotRetryableException):
        rest.fetch(timeout=5, **default_parameters)

    # first attempt fails and will not retry
    cnt.reset()
    default_parameters["no_retry"] = True
    ret = rest.fetch(timeout=5, **default_parameters)
    assert ret == {}
    assert cnt.c == 1  # failed on first call - did not retry
    assert rest._connection.errorhandler.called  # error


def test_secret_masking(caplog):
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )

    data = (
        '{"code": 12345,'
        ' "data": {"TOKEN": "_Y1ZNETTn5/qfUWj3Jedb", "PASSWORD": "dummy_pass"}'
        "}"
    )
    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": data,
    }

    class NotRetryableException(Exception):
        pass

    def fake_request_exec(**kwargs):
        return None

    # inject a fake method
    rest._request_exec = fake_request_exec

    # first two attempts will fail but third will success
    with caplog.at_level(logging.ERROR):
        ret = rest.fetch(timeout=10, **default_parameters)
    assert '"TOKEN": "****' in caplog.text
    assert '"PASSWORD": "****' in caplog.text
    assert ret == {}


def test_retry_connection_reset_error(caplog):
    connection = mock_connection(
        session_manager=get_mock_session_manager(allow_send=True)
    )
    connection.errorhandler = Mock(return_value=None)

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )

    data = (
        '{"code": 12345,'
        ' "data": {"TOKEN": "_Y1ZNETTn5/qfUWj3Jedb", "PASSWORD": "dummy_pass"}'
        "}"
    )
    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": data,
    }

    def error_recv_into(*args, **kwargs):
        raise OSError(104, "ECONNRESET")

    with patch.object(
        snowflake.connector.vendored.urllib3.contrib.pyopenssl.WrappedSocket,
        "recv_into",
        new=error_recv_into,
    ):
        with caplog.at_level(logging.DEBUG):
            rest.fetch(timeout=10, **default_parameters)

        assert (
            "shutting down requests session adapter due to connection aborted"
            in caplog.text
        )
        assert (
            "Ignored error caused by closing https connection failure"
            not in caplog.text
        )
        assert caplog.text.count("Starting new HTTPS connection") > 1


@pytest.mark.parametrize("next_action", ("RETRY", "ERROR"))
@patch("snowflake.connector.vendored.requests.sessions.Session.request")
def test_login_request_timeout(mockSessionRequest, next_action):
    """For login requests, all errors should be bubbled up as OperationalError for authenticator to handle"""
    mockSessionRequest.side_effect = mock_request_with_action(next_action)

    connection = mock_connection()
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )

    with pytest.raises(OperationalError):
        rest.fetch(
            method="post",
            full_url="https://testaccount.snowflakecomputing.com/session/v1/login-request",
            headers=dict(),
        )


@pytest.mark.parametrize(
    "next_action_result",
    (("RETRY", ServiceUnavailableError), ("ERROR", OperationalError)),
)
@patch("snowflake.connector.vendored.requests.sessions.Session.request")
def test_retry_request_timeout(mockSessionRequest, next_action_result):
    next_action, next_result = next_action_result
    mockSessionRequest.side_effect = mock_request_with_action(next_action, 5)
    # no backoff for testing
    connection = mock_connection(
        network_timeout=13,
        backoff_policy=zero_backoff,
    )
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )

    with pytest.raises(next_result):
        rest.fetch(
            method="post",
            full_url="https://testaccount.snowflakecomputing.com/queries/v1/query-request",
            headers=dict(),
        )

    # 13 seconds should be enough for authenticator to attempt thrice
    # however, loosen restrictions to avoid thread scheduling causing failure
    assert 1 < mockSessionRequest.call_count < 5


def test_sslerror_with_econnreset_retries():
    """Test that SSLError with ECONNRESET raises RetryRequest."""
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": '{"code": 12345}',
        "token": None,
    }

    # Test SSLError with ECONNRESET in the message
    econnreset_ssl_error = SSLError("Connection broken: ECONNRESET")
    session = MagicMock()
    session.request = Mock(side_effect=econnreset_ssl_error)

    with pytest.raises(RetryRequest, match="Connection broken: ECONNRESET"):
        rest._request_exec(session=session, **default_parameters)


def test_sslerror_without_econnreset_does_not_retry():
    """Test that SSLError without ECONNRESET does not retry but raises OperationalError."""
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": '{"code": 12345}',
        "token": None,
    }

    # Test SSLError without ECONNRESET in the message
    regular_ssl_error = SSLError("SSL handshake failed")
    session = MagicMock()
    session.request = Mock(side_effect=regular_ssl_error)

    # This should raise OperationalError, not RetryRequest
    with pytest.raises(OperationalError):
        rest._request_exec(session=session, **default_parameters)


def test_is_retryable_http_code_includes_307_308():
    """Test that 307 and 308 redirect status codes are considered retryable."""
    assert is_retryable_http_code(307) is True
    assert is_retryable_http_code(308) is True
    assert is_retryable_http_code(TEMPORARY_REDIRECT) is True
    assert is_retryable_http_code(PERMANENT_REDIRECT) is True


@pytest.mark.parametrize("status_code", [TEMPORARY_REDIRECT, PERMANENT_REDIRECT])
def test_redirect_status_raises_retry_request(status_code):
    """Test that 307/308 responses raise RetryRequest for non-login URLs."""
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    request_mock = MagicMock()
    type(request_mock).status_code = PropertyMock(return_value=status_code)
    request_mock.history = []

    session = MagicMock()
    session.request.return_value = request_mock

    with pytest.raises(RetryRequest):
        rest._request_exec(
            session=session,
            method="POST",
            full_url="https://testaccount.snowflakecomputing.com/queries/v1/query-request",
            headers={},
            data='{"code": 12345}',
            token=None,
        )


@pytest.mark.parametrize("status_code", [TEMPORARY_REDIRECT, PERMANENT_REDIRECT])
def test_redirect_login_raises_operational_error(status_code):
    """Test that 307/308 on login URLs raises OperationalError (not RetryRequest)."""
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    request_mock = MagicMock()
    type(request_mock).status_code = PropertyMock(return_value=status_code)
    request_mock.history = []

    session = MagicMock()
    session.request.return_value = request_mock

    with pytest.raises(OperationalError):
        rest._request_exec(
            session=session,
            method="POST",
            full_url="https://testaccount.snowflakecomputing.com/session/v1/login-request?request_id=abc",
            headers={},
            data='{"code": 12345}',
            token=None,
        )


def test_redirect_retry_succeeds_on_second_attempt():
    """Test that a redirect-triggered retry eventually succeeds using the original URL."""
    connection = mock_connection(backoff_policy=zero_backoff)
    connection.errorhandler = Mock(return_value=None)
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    call_count = 0

    def fake_request_exec(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RetryRequest(OtherHTTPRetryableError(errno=307))
        return {"success": True, "data": "valid data"}

    rest._request_exec = fake_request_exec

    ret = rest.fetch(
        method="POST",
        full_url="https://testaccount.snowflakecomputing.com/queries/v1/query-request",
        headers={},
        data='{"code": 12345}',
        timeout=10,
    )
    assert ret == {"success": True, "data": "valid data"}
    assert call_count == 2


def test_redirect_history_logged(caplog):
    """Test that redirect history is logged at debug level."""
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    # Create a mock redirect history entry
    hist_response = MagicMock()
    hist_response.status_code = 307
    hist_response.headers = {"Location": "/internal-redirect-target"}

    # Create the final 200 response with history
    output_data = {"success": True, "code": 12345}
    request_mock = MagicMock()
    type(request_mock).status_code = PropertyMock(return_value=OK)
    request_mock.json.return_value = output_data
    request_mock.history = [hist_response]

    session = MagicMock()
    session.request.return_value = request_mock

    with caplog.at_level(logging.DEBUG):
        ret = rest._request_exec(
            session=session,
            method="POST",
            full_url="https://testaccount.snowflakecomputing.com/queries/v1/query-request",
            headers={},
            data='{"code": 12345}',
            token=None,
        )

    assert ret == output_data
    assert (
        "Request was redirected: HTTP 307 to /internal-redirect-target" in caplog.text
    )
