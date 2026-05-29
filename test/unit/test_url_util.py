try:
    from snowflake.connector.url_util import (
        extract_top_level_domain_from_hostname,
        is_valid_url,
        url_encode_str,
    )
except ImportError:

    def is_valid_url(s):
        return False

    def url_encode_str(s):
        return ""


def test_url_validator():
    assert is_valid_url("https://ssoTestURL.okta.com")
    assert is_valid_url("https://ssoTestURL.okta.com:8080")
    assert is_valid_url("https://ssoTestURL.okta.com/testpathvalue")
    assert is_valid_url(
        "https://sso.abc.com/idp/startSSO.ping?PartnerSpId=https://xyz.eu-central-1.snowflakecomputing.com/"
    )

    assert not is_valid_url("-a Calculator")
    assert not is_valid_url("This is a random text")
    assert not is_valid_url("file://TestForFile")

    # non-string input
    assert not is_valid_url(None)
    assert not is_valid_url(123)

    # control characters / null bytes
    assert not is_valid_url("https://\x00evil.com")
    assert not is_valid_url("https://evil.com/path\x01")
    assert not is_valid_url("https://evil.com\nnewline")

    # embedded credentials are accepted (urlparse handles them safely)
    assert is_valid_url("https://user:pass@host.snowflakecomputing.com")

    # IPv4 and IPv6 literals
    assert is_valid_url("https://192.168.1.1/path")
    assert is_valid_url("https://[::1]:8080/path")


def test_encoder():
    assert url_encode_str("Hello @World") == "Hello+%40World"
    assert url_encode_str("Test//String") == "Test%2F%2FString"
    assert url_encode_str(None) == ""


def test_extract_top_level_domain_from_hostname():
    assert extract_top_level_domain_from_hostname("www.snowflakecomputing.com") == "com"
    assert extract_top_level_domain_from_hostname("www.snowflakecomputing.cn") == "cn"
    assert (
        extract_top_level_domain_from_hostname("www.snowflakecomputing.com.cn") == "cn"
    )
    assert extract_top_level_domain_from_hostname("a.b.c.d") == "d"
    assert extract_top_level_domain_from_hostname() == "com"
    assert extract_top_level_domain_from_hostname("a") == "com"
    assert extract_top_level_domain_from_hostname("a.b.c.def123") == "com"
