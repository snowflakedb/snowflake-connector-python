#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector.url_util import SnowflakeURLUtil


def test_url_validator():
    assert SnowflakeURLUtil.is_valid_url("https://ssoTestURL.okta.com")
    assert SnowflakeURLUtil.is_valid_url("https://ssoTestURL.okta.com:8080")
    assert SnowflakeURLUtil.is_valid_url("https://ssoTestURL.okta.com/testpathvalue")

    assert not SnowflakeURLUtil.is_valid_url("-a Calculator")
    assert not SnowflakeURLUtil.is_valid_url("This is a random text")
    assert not SnowflakeURLUtil.is_valid_url("file://TestForFile")


def test_encoder():
    assert SnowflakeURLUtil.url_encode_str("Hello @World") == "Hello+%40World"
    assert SnowflakeURLUtil.url_encode_str("Test//String") == "Test%2F%2FString"
