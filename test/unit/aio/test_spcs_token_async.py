from __future__ import annotations

import json
from unittest import mock

import pytest

import snowflake.connector.aio


async def _mock_post_factory(captured_requests):
    async def mock_post_request(url, headers, body, **kwargs):
        captured_requests.append((url, json.loads(body)))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN_ASYNC",
                "masterToken": "MASTER_TOKEN_ASYNC",
            },
        }

    return mock_post_request


async def _connect_and_capture(captured_requests):
    mock_post = await _mock_post_factory(captured_requests)
    with mock.patch(
        "snowflake.connector.aio._network.SnowflakeRestful._post_request",
        side_effect=mock_post,
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

    return [body for (url, body) in captured_requests if "login-request" in url]


@pytest.mark.skipolddriver
async def test_spcs_token_present_async(monkeypatch):
    """SPCS_TOKEN is injected into async login request when env var is set and file exists."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN_ASYNC")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_requests: list[tuple[str, dict]] = []
    login_bodies = await _connect_and_capture(captured_requests)

    assert len(login_bodies) == 1
    assert login_bodies[0]["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN_ASYNC"


@pytest.mark.skipolddriver
async def test_spcs_token_absent_async(monkeypatch):
    """SPCS_TOKEN is not added to async login request when file does not exist."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    monkeypatch.setattr(
        "snowflake.connector._utils.open",
        mock.Mock(side_effect=FileNotFoundError("No such file")),
        raising=False,
    )

    captured_requests: list[tuple[str, dict]] = []
    login_bodies = await _connect_and_capture(captured_requests)

    assert len(login_bodies) == 1
    assert "SPCS_TOKEN" not in login_bodies[0]["data"]


@pytest.mark.skipolddriver
async def test_not_in_spcs_async(monkeypatch):
    """SPCS_TOKEN is not added when SNOWFLAKE_RUNNING_INSIDE_SPCS is not set (async)."""
    monkeypatch.delenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", raising=False)
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN_ASYNC")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_requests: list[tuple[str, dict]] = []
    login_bodies = await _connect_and_capture(captured_requests)

    assert len(login_bodies) == 1
    assert "SPCS_TOKEN" not in login_bodies[0]["data"]


@pytest.mark.skipolddriver
async def test_spcs_token_with_whitespace_async(monkeypatch):
    """SPCS_TOKEN value has leading/trailing whitespace stripped (async)."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    mock_open = mock.mock_open(read_data="  \n TEST_SPCS_TOKEN_ASYNC \n  ")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_requests: list[tuple[str, dict]] = []
    login_bodies = await _connect_and_capture(captured_requests)

    assert len(login_bodies) == 1
    assert login_bodies[0]["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN_ASYNC"
