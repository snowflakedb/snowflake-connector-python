#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os

import pytest

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


@pytest.mark.skipif(not IS_LINUX, reason="The test is only for Linux platform")
@pytest.mark.skipolddriver
def test_basic_store(tmpdir):
    os.environ["SF_TEMPORARY_CREDENTIAL_CACHE_DIR"] = str(tmpdir)

    cache = FileTokenCache()
    cache.delete_temporary_credential_file()

    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    cache.store(TokenKey(HOST_1, USER_1, CRED_TYPE_1), CRED_1)
    cache.store(TokenKey(HOST_0, USER_1, CRED_TYPE_1), CRED_1)

    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    assert cache.retrieve(TokenKey(HOST_1, USER_1, CRED_TYPE_1)) == CRED_1
    assert cache.retrieve(TokenKey(HOST_0, USER_1, CRED_TYPE_1)) == CRED_1

    cache.delete_temporary_credential_file()


def test_delete_specific_item():
    """The old behavior of delete cache is deleting the whole cache file. Now we change it to partially deletion."""
    cache = FileTokenCache()
    cache.delete_temporary_credential_file()
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_0), CRED_0)
    cache.store(TokenKey(HOST_0, USER_0, CRED_TYPE_1), CRED_1)

    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0)) == CRED_0
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1

    cache.remove(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
    assert not cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_0))
    assert cache.retrieve(TokenKey(HOST_0, USER_0, CRED_TYPE_1)) == CRED_1
    cache.delete_temporary_credential_file()
