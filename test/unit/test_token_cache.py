#!/usr/bin/env python
from __future__ import annotations

import pytest

from snowflake.connector.token_cache import IS_LINUX, FileTokenCache, TokenCache


@pytest.mark.skipif(not IS_LINUX, reason="File token cache is supported only on Linux")
def test_file_token_cache_make_warns_incorrect_permissions_visible_on_stderr(
    capsys, tmp_path, monkeypatch
):
    cache_dir = tmp_path / ".cache" / "snowflake"
    cache_dir.mkdir(mode=0o740, parents=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    TokenCache.make()
    assert (
        ".cache/snowflake has incorrect permissions. 740 != 0700'. Skipping it in cache directory lookup."
        in capsys.readouterr().err
    )


@pytest.mark.skipif(not IS_LINUX, reason="File token cache is supported only on Linux")
def test_unsafe_skip_file_permissions_check_flag(capsys, tmp_path, monkeypatch):
    cache_dir = tmp_path / ".cache" / "snowflake"
    cache_dir.mkdir(mode=0o740, parents=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    token_cache = TokenCache.make(skip_file_permissions_check=True)
    # warning is surpressed
    assert "incorrect permissions" not in capsys.readouterr().err
    # _skip_file_permissions_check is set to True
    assert isinstance(token_cache, FileTokenCache)
    assert token_cache._skip_file_permissions_check
