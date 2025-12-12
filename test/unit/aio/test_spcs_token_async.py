from __future__ import annotations

import json
from unittest import mock

import pytest

import snowflake.connector.aio


@pytest.mark.skipolddriver
async def test_spcs_token_included_in_login_request_async(monkeypatch):
    """Verify that SPCS_TOKEN is injected into async login request body when present."""

    custom_path = "/custom/path/to/spcs_token"
    monkeypatch.setenv("SF_SPCS_TOKEN_PATH", custom_path)
    monkeypatch.setattr(
        "snowflake.connector._utils.os.path.isfile",
        lambda path: path == custom_path,
        raising=False,
    )
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN_ASYNC")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []

    async def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN_ASYNC",
                "masterToken": "MASTER_TOKEN_ASYNC",
            },
        }

    with mock.patch(
        "snowflake.connector.aio.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.aio.SnowflakeConnection(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        await conn.connect()
        assert conn._rest.token == "TOKEN_ASYNC"
        assert conn._rest.master_token == "MASTER_TOKEN_ASYNC"
        await conn.close()

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert body["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN_ASYNC"


@pytest.mark.skipolddriver
async def test_spcs_token_not_included_when_file_missing_async(monkeypatch):
    """Verify that SPCS_TOKEN is not added to async login request when file does not exist."""

    monkeypatch.delenv("SF_SPCS_TOKEN_PATH", raising=False)

    captured_bodies: list[dict] = []

    async def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN_ASYNC",
                "masterToken": "MASTER_TOKEN_ASYNC",
            },
        }

    with mock.patch(
        "snowflake.connector.aio.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.aio.SnowflakeConnection(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        await conn.connect()
        assert conn._rest.token == "TOKEN_ASYNC"
        assert conn._rest.master_token == "MASTER_TOKEN_ASYNC"
        await conn.close()

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert "SPCS_TOKEN" not in body["data"]


@pytest.mark.skipolddriver
async def test_spcs_token_default_path_used_when_env_unset_async(
    monkeypatch,
):
    """When SF_SPCS_TOKEN_PATH is not set, default path should be used (async)."""

    monkeypatch.delenv("SF_SPCS_TOKEN_PATH", raising=False)

    default_path = "/snowflake/session/spcs_token"
    monkeypatch.setattr(
        "snowflake.connector._utils.os.path.isfile",
        lambda path: path == default_path,
        raising=False,
    )
    mock_open = mock.mock_open(read_data="DEFAULT_PATH_SPCS_TOKEN_ASYNC")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []

    async def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN_ASYNC",
                "masterToken": "MASTER_TOKEN_ASYNC",
            },
        }

    with mock.patch(
        "snowflake.connector.aio.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.aio.SnowflakeConnection(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        await conn.connect()
        assert conn._rest.token == "TOKEN_ASYNC"
        assert conn._rest.master_token == "MASTER_TOKEN_ASYNC"
        await conn.close()

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert body["data"]["SPCS_TOKEN"] == "DEFAULT_PATH_SPCS_TOKEN_ASYNC"
