#!/usr/bin/env python
from __future__ import annotations

import pytest

from snowflake.connector.util_text import is_valid_account_identifier, parse_account


def test_parse_account_basic():
    assert parse_account("account1") == "account1"

    assert parse_account("account1.eu-central-1") == "account1"

    assert (
        parse_account("account1-jkabfvdjisoa778wqfgeruishafeuw89q.global") == "account1"
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("abc", True),
        ("ABC", True),
        ("a_b-c1", True),
        ("a.b", False),
        ("a/b", False),
        ("a\\b", False),
        ("", False),
        ("snowflakecomputing.com", False),
    ],
)
def test_is_valid_account_identifier(value, expected):
    assert is_valid_account_identifier(value) is expected
