from __future__ import annotations

import json
from unittest import mock

import pytest

import snowflake.connector


def _mock_post_factory(captured_bodies):
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

    return mock_post_request


def _connect_and_capture(captured_bodies):
    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        side_effect=_mock_post_factory(captured_bodies),
    ):
        conn = snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpwd",
            host="testaccount.snowflakecomputing.com",
        )
        assert conn._rest.token == "TOKEN"
        assert conn._rest.master_token == "MASTER_TOKEN"


@pytest.mark.skipolddriver
def test_spcs_token_present(monkeypatch):
    """SPCS_TOKEN is injected into the login request when env var is set and file exists."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []
    _connect_and_capture(captured_bodies)

    assert len(captured_bodies) == 1
    assert captured_bodies[0]["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN"


@pytest.mark.skipolddriver
def test_spcs_token_absent(monkeypatch):
    """SPCS_TOKEN is not added when env var is set but token file does not exist."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    monkeypatch.setattr(
        "snowflake.connector._utils.open",
        mock.Mock(side_effect=FileNotFoundError("No such file")),
        raising=False,
    )

    captured_bodies: list[dict] = []
    _connect_and_capture(captured_bodies)

    assert len(captured_bodies) == 1
    assert "SPCS_TOKEN" not in captured_bodies[0]["data"]


@pytest.mark.skipolddriver
def test_not_in_spcs(monkeypatch):
    """SPCS_TOKEN is not added when SNOWFLAKE_RUNNING_INSIDE_SPCS is not set."""
    monkeypatch.delenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", raising=False)
    mock_open = mock.mock_open(read_data="TEST_SPCS_TOKEN")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []
    _connect_and_capture(captured_bodies)

    assert len(captured_bodies) == 1
    assert "SPCS_TOKEN" not in captured_bodies[0]["data"]


@pytest.mark.skipolddriver
def test_spcs_token_with_whitespace(monkeypatch):
    """SPCS_TOKEN value has leading/trailing whitespace stripped."""
    monkeypatch.setenv("SNOWFLAKE_RUNNING_INSIDE_SPCS", "true")
    mock_open = mock.mock_open(read_data="  \n TEST_SPCS_TOKEN \n  ")
    monkeypatch.setattr("snowflake.connector._utils.open", mock_open, raising=False)

    captured_bodies: list[dict] = []
    _connect_and_capture(captured_bodies)

    assert len(captured_bodies) == 1
    assert captured_bodies[0]["data"]["SPCS_TOKEN"] == "TEST_SPCS_TOKEN"
