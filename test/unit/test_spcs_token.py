from __future__ import annotations

import json
from unittest import mock

import pytest

import snowflake.connector


@pytest.mark.skipolddriver
def test_spcs_token_included_in_login_request(monkeypatch):
    """Verify that SPCS_TOKEN is injected into the login request body when present."""

    # Use a custom SPCS token path and mock its existence and contents
    custom_path = "/custom/path/to/spcs_token"
    monkeypatch.setenv("SF_SPCS_TOKEN_PATH", custom_path)
    monkeypatch.setattr(
        "snowflake.connector._utils.os.path.isfile",
        lambda path: path == custom_path,
        raising=False,
    )
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []

    def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        # Return a minimal successful login response
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        assert conn._rest.token == "TOKEN"
        assert conn._rest.master_token == "MASTER_TOKEN"

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert body["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN"


@pytest.mark.skipolddriver
def test_spcs_token_not_included_when_file_missing(monkeypatch):
    """Verify that SPCS_TOKEN is not added when the token file does not exist."""

    # Ensure env var is unset so default path is used, but not created
    monkeypatch.delenv("SF_SPCS_TOKEN_PATH", raising=False)

    captured_bodies: list[dict] = []

    def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        assert conn._rest.token == "TOKEN"
        assert conn._rest.master_token == "MASTER_TOKEN"

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert "SPCS_TOKEN" not in body["data"]


@pytest.mark.skipolddriver
def test_spcs_token_default_path_used_when_env_unset(monkeypatch):
    """When SF_SPCS_TOKEN_PATH is not set, default path should be used."""

    # Ensure env var is unset so default path logic is exercised
    monkeypatch.delenv("SF_SPCS_TOKEN_PATH", raising=False)

    # Default SPCS path inside SPCS container
    default_path = "/snowflake/session/spcs_token"
    monkeypatch.setattr(
        "snowflake.connector._utils.os.path.isfile",
        lambda path: path == default_path,
        raising=False,
    )
    mock_open = mock.mock_open(read_data="DEFAULT_PATH_SPCS_TOKEN")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []

    def mock_post_request(url, headers, body, **kwargs):
        captured_bodies.append(json.loads(body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        side_effect=mock_post_request,
    ):
        conn = snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        assert conn._rest.token == "TOKEN"
        assert conn._rest.master_token == "MASTER_TOKEN"

    # Exactly one login-request should have been sent for this simple flow
    assert len(captured_bodies) == 1
    body = captured_bodies[0]
    assert body["data"]["SPCS_TOKEN"] == "DEFAULT_PATH_SPCS_TOKEN"
