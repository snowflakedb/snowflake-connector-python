#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

try:
    from snowflake.connector.url_util import is_valid_url, url_encode_str
except ImportError:

    def is_valid_url(s):
        return False


def test_url_validator():
    assert is_valid_url("https://ssoTestURL.okta.com")
    assert is_valid_url("https://ssoTestURL.okta.com:8080")
    assert is_valid_url("https://ssoTestURL.okta.com/testpathvalue")

    assert not is_valid_url("-a Calculator")
    assert not is_valid_url("This is a random text")
    assert not is_valid_url("file://TestForFile")


def test_encoder():
    assert url_encode_str("Hello @World") == "Hello+%40World"
    assert url_encode_str("Test//String") == "Test%2F%2FString"
    assert url_encode_str(None) == ""
