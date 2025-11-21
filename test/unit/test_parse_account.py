#!/usr/bin/env python
from __future__ import annotations

import pytest

from snowflake.connector import connect
from snowflake.connector.util_text import is_valid_account_identifier, parse_account


def test_parse_account_basic():
    assert parse_account("account1") == "account1"

    assert parse_account("account1.eu-central-1") == "account1"

    assert (
        parse_account("account1-jkabfvdjisoa778wqfgeruishafeuw89q.global") == "account1"
    )


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "aaa.bbb.ccc",
        "aaa.bbb.ccc.ddd" "ABC",
        "a_b-c1",
        "account1",
        "my_account",
        "my-account",
        "account_123",
        "ACCOUNT_NAME",
    ],
)
def test_is_valid_account_identifier(value):
    assert is_valid_account_identifier(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "a/b",
        "a\\b",
        "",
        "aa.bb.ccc/dddd",
        "account@domain",
        "account name",
        "account\ttab",
        "account\nnewline",
        "account:port",
        "account;semicolon",
        "account'quote",
        'account"doublequote',
    ],
)
def test_is_invalid_account_identifier(value):
    assert is_valid_account_identifier(value) is False
    with pytest.raises(ValueError) as err:
        connect(account=value, user="jdoe", password="***")

    assert "Invalid account identifier" in str(err)
