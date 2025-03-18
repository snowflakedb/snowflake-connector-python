#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import time

import pytest
from _pytest import pathlib

from snowflake.connector.compat import IS_LINUX

pytestmark = pytest.mark.skipif(not IS_LINUX, reason="Testing on linux only")

try:
    from snowflake.connector.token_cache import FileTokenCache, TokenKey, TokenType

    CRED_TYPE_0 = TokenType.ID_TOKEN
    CRED_TYPE_1 = TokenType.MFA_TOKEN
except ImportError:
    pass

HOST_0 = "host_0"
HOST_1 = "host_1"
USER_0 = "user_0"
USER_1 = "user_1"
CRED_0 = "cred_0"
CRED_1 = "cred_1"


@pytest.mark.skipolddriver
def test_basic_store(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    assert cache.cache_dir == pathlib.Path(tmpdir)
    cache.cache_file().unlink(missing_ok=True)

    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    cache.store(TokenKey(HOST_1, USER_1, CRED_TYPE_1), CRED_1)
    cache.store(TokenKey(HOST_0, USER_1, CRED_TYPE_1), CRED_1)

    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    assert cache.retrieve(TokenKey(HOST_1, USER_1, CRED_TYPE_1)) == CRED_1
    assert cache.retrieve(TokenKey(HOST_0, USER_1, CRED_TYPE_1)) == CRED_1

    cache.cache_file().unlink(missing_ok=True)


@pytest.mark.skipif(not IS_LINUX, reason="The test is only for Linux platform")
def test_delete_specific_item(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_1), CRED_1)

    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1

    cache.remove(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
    assert not cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1
    cache.cache_file().unlink(missing_ok=True)


def test_malformed_json_cache(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    cache.cache_file().touch(0o600)
    invalid_json = "[}"
    cache.cache_file().write_text(invalid_json)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0


def test_malformed_utf_cache(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    cache.cache_file().touch(0o600)
    invalid_utf_sequence = bytes.fromhex("c0af")
    cache.cache_file().write_bytes(invalid_utf_sequence)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0


def test_cache_dir_is_not_a_directory(tmpdir, monkeypatch):
    file = pathlib.Path(str(tmpdir)) / "file"
    file.touch()
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(file))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    cache_dir = FileTokenCache.find_cache_dir()
    assert cache_dir is None
    file.unlink()


def test_cache_dir_does_not_exist(tmpdir, monkeypatch):
    directory = pathlib.Path(str(tmpdir)) / "dir"
    directory.unlink(missing_ok=True)
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(directory))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    cache_dir = FileTokenCache.find_cache_dir()
    assert cache_dir is None


def test_cache_dir_incorrect_permissions(tmpdir, monkeypatch):
    directory = pathlib.Path(str(tmpdir)) / "dir"
    directory.unlink(missing_ok=True)
    directory.touch(0o777)
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(directory))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    cache_dir = FileTokenCache.find_cache_dir()
    assert cache_dir is None
    directory.unlink()


def test_cache_file_incorrect_permissions(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    cache.cache_file().touch(0o777)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
    assert len(cache.cache_file().read_text("utf-8")) == 0
    cache.cache_file().unlink()


def test_cache_dir_xdg_cache_home(tmpdir, monkeypatch):
    monkeypatch.delenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    assert cache.cache_dir == pathlib.Path(str(tmpdir)) / "snowflake"
    assert (
        cache.cache_file()
        == pathlib.Path(str(tmpdir)) / "snowflake" / "credential_cache_v1.json"
    )
    assert (
        cache.lock_file()
        == pathlib.Path(str(tmpdir)) / "snowflake" / "credential_cache_v1.json.lck"
    )
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    cache.cache_file().unlink()


def test_cache_dir_home(tmpdir, monkeypatch):
    monkeypatch.delenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.cache_file().unlink(missing_ok=True)
    assert cache.cache_dir == pathlib.Path(str(tmpdir)) / ".cache" / "snowflake"
    assert (
        cache.cache_file()
        == pathlib.Path(str(tmpdir))
        / ".cache"
        / "snowflake"
        / "credential_cache_v1.json"
    )
    assert (
        cache.lock_file()
        == pathlib.Path(str(tmpdir))
        / ".cache"
        / "snowflake"
        / "credential_cache_v1.json.lck"
    )
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0


def test_file_lock(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    cache.lock_file().mkdir(0o700)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
    assert cache.lock_file().exists()
    cache.lock_file().rmdir()


def test_file_lock_stale(tmpdir, monkeypatch):
    monkeypatch.setenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir))
    cache = FileTokenCache.make()
    assert cache
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    cache.lock_file().mkdir(0o700)
    time.sleep(1)
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    assert not cache.lock_file().exists()
