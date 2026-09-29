#!/usr/bin/env python
from __future__ import annotations

import logging
from textwrap import dedent
from unittest.mock import MagicMock

import pytest

import snowflake.connector
from snowflake.connector import ssl_wrap_socket
from snowflake.connector._ocsp_mode import (
    IGNORED_OCSP_SUPPORT_PARAMS_WARNING,
    ignored_ocsp_support_params,
    resolve_ocsp_mode,
    snapshot_ocsp_explicit_params,
)
from snowflake.connector.constants import OCSPMode
from snowflake.connector.network import SnowflakeRestful

from .test_connection import fake_connector, write_temp_file


@pytest.mark.parametrize(
    "kwargs,expected_mode,expected_disable_property,expect_warning",
    [
        ({}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        ({"ocsp_fail_open": None}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        ({"ocsp_fail_open": True}, OCSPMode.FAIL_OPEN, False, False),
        ({"ocsp_fail_open": False}, OCSPMode.FAIL_CLOSED, False, False),
        ({"disable_ocsp_checks": False}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        ({"disable_ocsp_checks": True}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        ({"insecure_mode": True}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        ({"insecure_mode": False}, OCSPMode.DISABLE_OCSP_CHECKS, True, False),
        (
            {"disable_ocsp_checks": False, "ocsp_fail_open": True},
            OCSPMode.FAIL_OPEN,
            False,
            False,
        ),
        (
            {"insecure_mode": False, "ocsp_fail_open": False},
            OCSPMode.FAIL_CLOSED,
            False,
            False,
        ),
        (
            {"disable_ocsp_checks": True, "ocsp_fail_open": False},
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            False,
        ),
        (
            {"disable_ocsp_checks": True, "ocsp_fail_open": True},
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            False,
        ),
        (
            {"insecure_mode": True, "ocsp_fail_open": True},
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            False,
        ),
        (
            {"ocsp_response_cache_filename": "/tmp/ocsp_cache.json"},
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            True,
        ),
        (
            {"ocsp_root_certs_dict_lock_timeout": 1},
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            True,
        ),
        (
            {
                "ocsp_response_cache_filename": "/tmp/ocsp_cache.json",
                "ocsp_fail_open": True,
            },
            OCSPMode.FAIL_OPEN,
            False,
            False,
        ),
        (
            {
                "ocsp_response_cache_filename": "/tmp/ocsp_cache.json",
                "disable_ocsp_checks": True,
            },
            OCSPMode.DISABLE_OCSP_CHECKS,
            True,
            False,
        ),
    ],
)
def test_resolve_ocsp_mode_from_kwargs(
    monkeypatch,
    kwargs,
    expected_mode,
    expected_disable_property,
    expect_warning,
    caplog,
):
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    caplog.set_level(logging.WARNING, "snowflake.connector.connection")
    conn = fake_connector(**kwargs)
    try:
        assert conn._ocsp_mode() == expected_mode
        assert conn.disable_ocsp_checks is expected_disable_property
        assert conn.insecure_mode is expected_disable_property
        warning = IGNORED_OCSP_SUPPORT_PARAMS_WARNING.split("{params}")[0]
        if expect_warning:
            assert warning in caplog.text
            for name in kwargs:
                if name in {
                    "ocsp_response_cache_filename",
                    "ocsp_root_certs_dict_lock_timeout",
                }:
                    assert name in caplog.text
        else:
            assert warning not in caplog.text
    finally:
        conn.close()


def test_sf_ocsp_fail_open_env_does_not_enable_ocsp(monkeypatch):
    monkeypatch.setenv("SF_OCSP_FAIL_OPEN", "true")
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    conn = fake_connector()
    try:
        assert conn._ocsp_mode() == OCSPMode.DISABLE_OCSP_CHECKS
        assert conn.disable_ocsp_checks is True
    finally:
        conn.close()


def test_toml_ocsp_fail_open_is_explicit(monkeypatch, tmp_path):
    connections_file = write_temp_file(
        tmp_path / "connections.toml",
        contents=dedent(
            """\
        [default]
        account = "my_account_1"
        user = "user"
        password = "testpassword"
        authenticator = "snowflake"
        ocsp_fail_open = true
        """
        ),
    )
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    conn = snowflake.connector.connect(connections_file_path=connections_file)
    try:
        assert conn._ocsp_mode() == OCSPMode.FAIL_OPEN
        assert conn.disable_ocsp_checks is False
        assert conn.ocsp_fail_open is True
    finally:
        conn.close()


def test_forwarded_default_configuration_does_not_opt_in(monkeypatch):
    from snowflake.connector.connection import DEFAULT_CONFIGURATION

    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    default, accepted = DEFAULT_CONFIGURATION["ocsp_fail_open"]
    assert default is None
    assert type(None) in accepted
    conn = fake_connector(
        disable_ocsp_checks=DEFAULT_CONFIGURATION["disable_ocsp_checks"][0],
        ocsp_fail_open=default,
    )
    try:
        assert conn.ocsp_fail_open is None
        assert conn._ocsp_mode() == OCSPMode.DISABLE_OCSP_CHECKS
        assert conn.disable_ocsp_checks is True
    finally:
        conn.close()


def test_toml_disable_ocsp_checks_false_is_not_opt_in(monkeypatch, tmp_path):
    connections_file = write_temp_file(
        tmp_path / "connections.toml",
        contents=dedent(
            """\
        [default]
        account = "my_account_1"
        user = "user"
        password = "testpassword"
        authenticator = "snowflake"
        disable_ocsp_checks = false
        """
        ),
    )
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    conn = snowflake.connector.connect(connections_file_path=connections_file)
    try:
        assert conn._ocsp_mode() == OCSPMode.DISABLE_OCSP_CHECKS
        assert conn.disable_ocsp_checks is True
    finally:
        conn.close()


def test_default_feature_ocsp_mode_is_disabled():
    assert ssl_wrap_socket.DEFAULT_OCSP_MODE == OCSPMode.DISABLE_OCSP_CHECKS
    # FEATURE_OCSP_MODE is process-global. Isolate it here so an earlier
    # fail-open connection cannot make this assertion flake.
    orig = ssl_wrap_socket.FEATURE_OCSP_MODE
    try:
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.DISABLE_OCSP_CHECKS
    finally:
        ssl_wrap_socket.FEATURE_OCSP_MODE = orig


def test_feature_ocsp_mode_default_does_not_overwrite_opt_in(monkeypatch):
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    fail_open = fake_connector(ocsp_fail_open=True)
    disabled = fake_connector()
    fail_closed = fake_connector(ocsp_fail_open=False)
    try:
        # Construction already applied each connection's mode. Reset so
        # this test covers REST-client apply order, not leftover state.
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE
        SnowflakeRestful(connection=fail_open, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_OPEN
        SnowflakeRestful(connection=disabled, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_OPEN
        SnowflakeRestful(connection=fail_closed, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_CLOSED
    finally:
        fail_open.close()
        disabled.close()
        fail_closed.close()
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE


def test_apply_feature_ocsp_mode_does_not_weaken_fail_closed():
    orig = ssl_wrap_socket.FEATURE_OCSP_MODE
    try:
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE
        assert (
            ssl_wrap_socket.apply_feature_ocsp_mode(OCSPMode.FAIL_OPEN)
            == OCSPMode.FAIL_OPEN
        )
        assert (
            ssl_wrap_socket.apply_feature_ocsp_mode(OCSPMode.FAIL_CLOSED)
            == OCSPMode.FAIL_CLOSED
        )
        assert (
            ssl_wrap_socket.apply_feature_ocsp_mode(OCSPMode.FAIL_OPEN)
            == OCSPMode.FAIL_CLOSED
        )
        assert (
            ssl_wrap_socket.apply_feature_ocsp_mode(OCSPMode.DISABLE_OCSP_CHECKS)
            == OCSPMode.FAIL_CLOSED
        )
    finally:
        ssl_wrap_socket.FEATURE_OCSP_MODE = orig


def test_feature_ocsp_mode_fail_open_does_not_overwrite_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
    )
    fail_closed = fake_connector(ocsp_fail_open=False)
    fail_open = fake_connector(ocsp_fail_open=True)
    disabled = fake_connector()
    try:
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE
        SnowflakeRestful(connection=fail_closed, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_CLOSED
        SnowflakeRestful(connection=fail_open, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_CLOSED
        SnowflakeRestful(connection=disabled, session_manager=MagicMock())
        assert ssl_wrap_socket.FEATURE_OCSP_MODE == OCSPMode.FAIL_CLOSED
    finally:
        fail_closed.close()
        fail_open.close()
        disabled.close()
        ssl_wrap_socket.FEATURE_OCSP_MODE = ssl_wrap_socket.DEFAULT_OCSP_MODE


def test_resolver_helpers_do_not_need_a_connection():
    assert (
        resolve_ocsp_mode(
            explicit=snapshot_ocsp_explicit_params({}),
            disable_ocsp_checks=False,
            ocsp_fail_open=None,
        )
        == OCSPMode.DISABLE_OCSP_CHECKS
    )
    assert ignored_ocsp_support_params({"ocsp_response_cache_filename"}) == (
        "ocsp_response_cache_filename",
    )
    assert ignored_ocsp_support_params({"disable_ocsp_checks"}) == ()
    assert (
        ignored_ocsp_support_params(
            {"disable_ocsp_checks", "ocsp_response_cache_filename"}
        )
        == ()
    )


def test_false_disable_is_not_an_opt_in():
    assert (
        resolve_ocsp_mode(
            explicit={"disable_ocsp_checks"},
            disable_ocsp_checks=False,
            ocsp_fail_open=None,
        )
        == OCSPMode.DISABLE_OCSP_CHECKS
    )
    assert (
        resolve_ocsp_mode(
            explicit={"insecure_mode"},
            disable_ocsp_checks=False,
            ocsp_fail_open=None,
            insecure_mode=False,
        )
        == OCSPMode.DISABLE_OCSP_CHECKS
    )
    assert (
        resolve_ocsp_mode(
            explicit={"disable_ocsp_checks", "insecure_mode"},
            disable_ocsp_checks=False,
            ocsp_fail_open=None,
            insecure_mode=False,
        )
        == OCSPMode.DISABLE_OCSP_CHECKS
    )
    assert (
        resolve_ocsp_mode(
            explicit={"disable_ocsp_checks", "ocsp_fail_open"},
            disable_ocsp_checks=False,
            ocsp_fail_open=True,
        )
        == OCSPMode.FAIL_OPEN
    )
    assert (
        resolve_ocsp_mode(
            explicit={"ocsp_fail_open"},
            disable_ocsp_checks=False,
            ocsp_fail_open=None,
        )
        == OCSPMode.DISABLE_OCSP_CHECKS
    )
