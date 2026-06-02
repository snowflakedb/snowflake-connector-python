import pytest

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


@pytest.mark.parametrize(
    "url",
    [
        "https://ssoTestURL.okta.com",
        "https://ssoTestURL.okta.com:8080",
        "https://ssoTestURL.okta.com/testpathvalue",
        "https://sso.abc.com/idp/startSSO.ping?PartnerSpId=https://xyz.eu-central-1.snowflakecomputing.com/",
        # embedded credentials are accepted (urlparse handles them safely)
        "https://user:pass@host.snowflakecomputing.com",
        # IPv4 and IPv6 literals
        "https://192.168.1.1/path",
        "https://[::1]:8080/path",
        # localhost / internal names
        "https://localhost",
        "https://localhost:3000/callback",
        "https://intranet/path",
        # query / fragment handling
        "https://example.com/path?x=1&y=2",
        "https://example.com/path#fragment",
        "https://example.com/path?next=https://evil.com",
        # case normalization and punycode IDN
        "HTTPS://EXAMPLE.COM/Path",
        "https://xn--bcher-kva.example",
        # percent-encoded path
        "https://example.com/%00",
        "https://example.com/%0a",
    ],
)
def test_url_validator_accepts(url):
    assert is_valid_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "-a Calculator",
        "This is a random text",
        "file://TestForFile",
        # non-string input
        None,
        123,
        # control characters / null bytes
        "https://\x00evil.com",
        "https://evil.com/path\x01",
        "https://evil.com\nnewline",
        # unsupported / missing scheme
        "ftp://evil.com",
        "javascript:alert(1)",
        "mailto:test@example.com",
        "//evil.com/path",
        "host.snowflakecomputing.com",
        # empty host
        "https://",
        "https:///path",
        # leading whitespace and CRLF header injection
        " https://evil.com",
        "\thttps://evil.com",
        "https://evil.com\r\nHost: attacker.com",
        # malformed IPv6 (missing closing bracket)
        "https://[::1",
    ],
)
def test_url_validator_rejects(url):
    assert not is_valid_url(url)


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
