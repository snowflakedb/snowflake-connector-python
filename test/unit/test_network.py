#!/usr/bin/env python
import io
import json
import unittest.mock
import uuid
from test.unit.mock_utils import mock_connection

import pytest

from snowflake.connector.errors import HttpError
from src.snowflake.connector.network import SnowflakeRestfulJsonEncoder

try:
    from snowflake.connector import Error
    from snowflake.connector.network import (
        PATWithExternalSessionAuth,
        SnowflakeAuth,
        SnowflakeRestful,
    )
    from snowflake.connector.vendored.requests import HTTPError, Response
except ImportError:
    # skipping old driver test
    pass

pytestmark = pytest.mark.skipolddriver


def test_fetch():
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

    failed_response = Response()
    failed_response.status_code = 409
    failed_response.raw = io.StringIO("error")
    failed_response.url = default_parameters["full_url"]
    failed_response.reason = "conflict"
    with unittest.mock.patch(
        "snowflake.connector.vendored.requests.sessions.Session.request",
        return_value=failed_response,
    ):
        with pytest.raises(HTTPError) as exc:
            rest.fetch(**default_parameters, raise_raw_http_failure=True)
        assert exc.value.response.status_code == failed_response.status_code
        assert exc.value.response.reason == failed_response.reason

        with pytest.raises(HTTPError) as exc:
            rest.fetch(**default_parameters, raise_raw_http_failure=True, no_retry=True)
        assert exc.value.response.status_code == failed_response.status_code
        assert exc.value.response.reason == failed_response.reason

        # if not setting the flag, the function returns an empty dictionary
        assert (
            rest.fetch(
                **default_parameters, raise_raw_http_failure=False, no_retry=True
            )
            == {}
        )
        assert rest.fetch(**default_parameters, no_retry=True) == {}
        # if no retry is set to False, the function raises an HttpError
        with pytest.raises(HttpError):
            rest.fetch(**default_parameters, no_retry=False)


@pytest.mark.parametrize(
    "u",
    [
        uuid.uuid1(),
        uuid.uuid3(uuid.NAMESPACE_URL, "www.snowflake.com"),
        uuid.uuid4(),
        uuid.uuid5(uuid.NAMESPACE_URL, "www.snowflake.com"),
    ],
)
def test_json_serialize_uuid(u):
    expected = f'{{"u": "{u}", "a": 42}}'

    assert (json.dumps(u, cls=SnowflakeRestfulJsonEncoder)) == f'"{u}"'

    assert json.dumps({"u": u, "a": 42}, cls=SnowflakeRestfulJsonEncoder) == expected


def test_fetch_auth():
    """Test checks that PATWithExternalSessionAuth is used instead of SnowflakeAuth when external_session_id is provided."""
    connection = mock_connection()
    rest = SnowflakeRestful(
        host="test.snowflakecomputing.com", port=443, connection=connection
    )
    rest._token = "test-token"
    rest._master_token = "test-master-token"

    captured_auth = None

    def mock_request(**kwargs):
        nonlocal captured_auth
        captured_auth = kwargs.get("auth")
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        return mock_response

    with unittest.mock.patch(
        "snowflake.connector.network.requests.Session"
    ) as mock_session_class:
        mock_session = unittest.mock.MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request = mock_request

        # Call fetch without providing external_session_id - should use SnowflakeAuth
        rest.fetch(
            method="POST",
            full_url="https://test.snowflakecomputing.com/test",
            headers={},
            data={},
        )
    assert isinstance(captured_auth, SnowflakeAuth)

    with unittest.mock.patch(
        "snowflake.connector.network.requests.Session"
    ) as mock_session_class:
        mock_session = unittest.mock.MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request = mock_request

        # Call fetch with providing external_session_id - should use PATWithExternalSessionAuth
        rest.fetch(
            method="POST",
            full_url="https://test.snowflakecomputing.com/test",
            headers={},
            data={},
            external_session_id="dummy-external-session-id",
        )
    assert isinstance(captured_auth, PATWithExternalSessionAuth)
    assert captured_auth.external_session_id == "dummy-external-session-id"
