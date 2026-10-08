import pytest

from snowflake.connector.vendored.requests import check_compatibility

# A urllib3 version that satisfies the remaining lower bound (major >= 1).
_URLLIB3 = "2.6.3"


@pytest.mark.parametrize(
    ("chardet_version", "charset_normalizer_version"),
    [
        ("3.0.2", None),
        ("5.2.0", None),
        # chardet is preferred when both are present, so 7.x must not warn
        # even alongside a current charset_normalizer (SNOW-3559506).
        ("7.4.3", "3.4.7"),
        (None, "2.0.0"),
        (None, "3.4.7"),
        (None, "4.0.0"),
    ],
)
def test_check_compatibility_accepts_current_char_detection(
    chardet_version, charset_normalizer_version
):
    check_compatibility(_URLLIB3, chardet_version, charset_normalizer_version)


@pytest.mark.parametrize(
    ("chardet_version", "charset_normalizer_version"),
    [
        ("3.0.1", None),
        ("2.3.0", "3.4.7"),
        (None, "1.9.9"),
    ],
)
def test_check_compatibility_rejects_char_detection_below_minimum(
    chardet_version, charset_normalizer_version
):
    with pytest.raises(AssertionError):
        check_compatibility(_URLLIB3, chardet_version, charset_normalizer_version)
