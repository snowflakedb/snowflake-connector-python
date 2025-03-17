#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os

import pytest
from _pytest import pathlib

from snowflake.connector.compat import IS_LINUX

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


class EnvOverride:
    def __init__(self, env, value):
        self.env = env
        self.value = value
        self.active = False

    def __enter__(self):
        self.active = True
        self.oldValue = os.environ.get(self.env)
        if self.value is None:
            os.environ.pop(self.env, None)
        else:
            os.environ[self.env] = self.value

    def __exit__(self, type, value, traceback):
        if self.active:
            if self.oldValue is not None:
                os.environ[self.env] = self.oldValue
            self.active = False


@pytest.mark.skipif(not IS_LINUX, reason="The test is only for Linux platform")
@pytest.mark.skipolddriver
def test_basic_store(tmpdir):
    with EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir)):
        cache = FileTokenCache()
        assert cache.cache_dir == pathlib.Path(tmpdir)
        cache.cache_file().unlink(missing_ok=True)

        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        cache.store(TokenKey(HOST_1, USER_1, CRED_TYPE_1), CRED_1)
        cache.store(TokenKey(HOST_0, USER_1, CRED_TYPE_1), CRED_1)

        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
        assert cache.retrieve(TokenKey(HOST_1, USER_1, CRED_TYPE_1)) == CRED_1
        assert cache.retrieve(TokenKey(HOST_0, USER_1, CRED_TYPE_1)) == CRED_1

        cache.cache_file().unlink(missing_ok=True)


def test_delete_specific_item(tmpdir):
    """The old behavior of delete cache is deleting the whole cache file. Now we change it to partially deletion."""
    with EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir)):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_1), CRED_1)

        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1

        cache.remove(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
        assert not cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1
        cache.cache_file().unlink(missing_ok=True)


def test_malformed_json_cache(tmpdir):
    with EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir)):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        cache.cache_file().touch(0o600)
        invalid_json = "[}"
        cache.cache_file().write_text(invalid_json)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0


def test_malformed_utf_cache(tmpdir):
    with EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir)):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        cache.cache_file().touch(0o600)
        invalid_utf_sequence = bytes.fromhex("c0af")
        cache.cache_file().write_bytes(invalid_utf_sequence)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0


def test_cache_dir_is_not_a_directory(tmpdir):
    file = pathlib.Path(str(tmpdir)) / "file"
    file.touch()
    with (
        EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(file)),
        EnvOverride("XDG_CACHE_HOME", None),
        EnvOverride("HOME", None),
    ):
        cache = FileTokenCache()
        assert cache.cache_dir is None
    file.unlink()


def test_cache_dir_does_not_exist(tmpdir):
    directory = pathlib.Path(str(tmpdir)) / "dir"
    directory.unlink(missing_ok=True)
    with (
        EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(directory)),
        EnvOverride("XDG_CACHE_HOME", None),
        EnvOverride("HOME", None),
    ):
        cache = FileTokenCache()
        assert cache.cache_dir is None


def test_cache_dir_incorrect_permissions(tmpdir):
    directory = pathlib.Path(str(tmpdir)) / "dir"
    directory.unlink(missing_ok=True)
    directory.touch(0o777)
    with (
        EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(directory)),
        EnvOverride("XDG_CACHE_HOME", None),
        EnvOverride("HOME", None),
    ):
        cache = FileTokenCache()
        assert cache.cache_dir is None
    directory.unlink()


def test_cache_file_incorrect_permissions(tmpdir):
    with EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", str(tmpdir)):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        cache.cache_file().touch(0o777)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) is None
        assert len(cache.cache_file().read_text("utf-8")) == 0
        cache.cache_file().unlink()


def test_cache_dir_xdg_cache_home(tmpdir):
    with (
        EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", None),
        EnvOverride("XDG_CACHE_HOME", str(tmpdir)),
    ):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        assert cache.cache_dir == pathlib.Path(str(tmpdir)) / "snowflake"
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
        cache.cache_file().unlink()


def test_cache_dir_home(tmpdir):
    with (
        EnvOverride("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", None),
        EnvOverride("XDG_CACHE_HOME", None),
        EnvOverride("HOME", str(tmpdir)),
    ):
        cache = FileTokenCache()
        cache.cache_file().unlink(missing_ok=True)
        assert cache.cache_dir == pathlib.Path(str(tmpdir)) / ".cache" / "snowflake"
        cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
        assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
