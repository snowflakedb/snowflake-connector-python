#!/usr/bin/env python
from __future__ import annotations

import logging
from unittest import mock

import pytest

from snowflake.connector.secret_detector import SecretDetector


def basic_masking(test_str):
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_str)
    assert not masked
    assert err_str is None
    assert masked_str == test_str


def test_none_string():
    basic_masking(None)


def test_empty_string():
    basic_masking("")


def test_no_masking():
    basic_masking("This string is innocuous")


@mock.patch.object(
    SecretDetector,
    "mask_connection_token",
    mock.Mock(side_effect=Exception("Test exception")),
)
def test_exception_in_masking():
    test_str = "This string will raise an exception"
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_str)
    assert masked
    assert err_str == "Test exception"
    assert masked_str == "Test exception"


def exception_in_log_masking():
    test_str = "This string will raise an exception"
    log_record = logging.LogRecord(
        SecretDetector.__name__,
        logging.DEBUG,
        "test_unit_log_secret_detector.py",
        45,
        test_str,
        list(),
        None,
    )
    log_record.asctime = "2003-07-08 16:49:45,896"
    secret_detector = SecretDetector()
    sanitized_log = secret_detector.format(log_record)
    assert "Test exception" in sanitized_log
    assert "secret_detector.py" in sanitized_log
    assert "sanitize_log_str" in sanitized_log
    assert test_str not in sanitized_log


@mock.patch.object(
    SecretDetector,
    "mask_connection_token",
    mock.Mock(side_effect=Exception("Test exception")),
)
def test_exception_in_secret_detector_while_log_masking():
    exception_in_log_masking()


@mock.patch.object(
    SecretDetector, "mask_secrets", mock.Mock(side_effect=Exception("Test exception"))
)
def test_exception_while_log_masking():
    exception_in_log_masking()


def test_mask_token():
    long_token = (
        "_Y1ZNETTn5/qfUWj3Jedby7gipDzQs=U"
        "KyJH9DS=nFzzWnfZKGV+C7GopWCGD4Lj"
        "OLLFZKOE26LXHDt3pTi4iI1qwKuSpf/F"
        "mClCMBSissVsU3Ei590FP0lPQQhcSGcD"
        "u69ZL_1X6e9h5z62t/iY7ZkII28n2qU="
        "nrBJUgPRCIbtJQkVJXIuOHjX4G5yUEKj"
        "ZBAx4w6=_lqtt67bIA=o7D=oUSjfywsR"
        "FoloNIkBPXCwFTv+1RVUHgVA2g8A9Lw5"
        "XdJYuI8vhg=f0bKSq7AhQ2Bh"
    )

    rsa_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0pCa0rw1n4GBjylx\n"
        "sBJPVCrsKO7SowkgJ52Lc8K3hMHNKXvYiqwgizbXFBQA27kvpEVSeRQVC3FAPRU5\n"
        "gjtLRwIDAQABAkBHZbz5o9PS6AjUUEs6VpsLgRpersxBeACtLiBw+h9cJfUerR//\n"
        "tTmNsQ9LlamMu2lOlfbO3R2J45ybF7z94A+hAiEA8piucvAlo9YJ4VViQGRTVvr+\n"
        "xZKekSEYRJBn2czeP+kCIQDeMt1PVk/p0NEcNvQMbO0vJ3+U+lITJRwmtJ9Fs1Lj\n"
        "rwIgJeTdkwyaBI6BepY4w7AoKHUKaNgvNqJBxSv9XNMYgEkCIG2rl1YgWOMkAQI3\n"
        "EW/Ml6jtiugiQT5X07Q69F33q5LbAiEArZM7htafpt0RVia+nC9aY+73wpW0Be9e\n"
        "pDz0yVv8s/Q=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    json_token = (
        "{'TOKEN': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFt"
        "ZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'}"
    )

    masked, masked_str, err_str = SecretDetector.mask_secrets(rsa_key)
    assert masked
    assert err_str is None
    assert (
        masked_str == "-----BEGIN PRIVATE KEY-----\\nXXXX\\n-----END PRIVATE KEY-----\n"
    )

    token_str_w_prefix = "Token =" + long_token
    masked, masked_str, err_str = SecretDetector.mask_secrets(token_str_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "Token =****"

    id_token_str_w_prefix = "idToken : " + long_token
    masked, masked_str, err_str = SecretDetector.mask_secrets(id_token_str_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "idToken : ****"

    session_token_w_prefix = "sessionToken : " + long_token
    masked, masked_str, err_str = SecretDetector.mask_secrets(session_token_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "sessionToken : ****"

    master_token_w_prefix = "masterToken : " + long_token
    masked, masked_str, err_str = SecretDetector.mask_secrets(master_token_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "masterToken : ****"

    assertion_w_prefix = "assertion content:" + long_token
    masked, masked_str, err_str = SecretDetector.mask_secrets(assertion_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "assertion content:****"

    masked, masked_str, err_str = SecretDetector.mask_secrets(json_token)
    assert masked
    assert err_str is None
    assert masked_str == "{'TOKEN': '****'}"


def test_mask_token_with_version_hint_prefix():
    # A real session token carries version/hint detail ahead of the token itself.
    # Without ':' in the value group the whole token was left unmasked.
    token_with_hint = "token=ver:1-hint:1036-abcd1234efgh5678"
    masked, masked_str, err_str = SecretDetector.mask_secrets(token_with_hint)
    assert masked
    assert err_str is None
    assert masked_str == "token=****"


def test_token_false_positives():
    false_positive_token_str = (
        "2020-04-30 23:06:04,069 - MainThread auth.py:397"
        " - write_temporary_credential() - DEBUG - no ID "
        "token is given when try to store temporary credential"
    )

    masked, masked_str, err_str = SecretDetector.mask_secrets(false_positive_token_str)
    assert not masked
    assert err_str is None
    assert masked_str == false_positive_token_str


def test_password():
    random_password = "Fh[+2J~AcqeqW%?"
    random_password_w_prefix = "password:" + random_password
    masked, masked_str, err_str = SecretDetector.mask_secrets(random_password_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "password:****"

    random_password_caps = "PASSWORD:" + random_password
    masked, masked_str, err_str = SecretDetector.mask_secrets(random_password_caps)
    assert masked
    assert err_str is None
    assert masked_str == "PASSWORD:****"

    random_password_mix_case = "PassWorD:" + random_password
    masked, masked_str, err_str = SecretDetector.mask_secrets(random_password_mix_case)
    assert masked
    assert err_str is None
    assert masked_str == "PassWorD:****"

    random_password_equal_sign = "password = " + random_password
    masked, masked_str, err_str = SecretDetector.mask_secrets(
        random_password_equal_sign
    )
    assert masked
    assert err_str is None
    assert masked_str == "password = ****"

    random_password = "Fh[+2J~AcqeqW%?"
    random_password_w_prefix = "pwd:" + random_password
    masked, masked_str, err_str = SecretDetector.mask_secrets(random_password_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "pwd:****"

    random_password_truncated = "password=Afs..."
    masked, masked_str, err_str = SecretDetector.mask_secrets(random_password_truncated)
    assert masked
    assert err_str is None
    assert masked_str == "password=****"


@pytest.mark.parametrize(
    "false_positive_str",
    [
        "...no ID password was not given",
        "...no ID proxyPassword was not given",
        "...no ID private_key_pwd was not given",
    ],
)
def test_password_false_positives(false_positive_str):
    # Ported from .NET's SecretDetectorTest.TestPasswordFalsePositive. Ordinary log
    # prose must survive: the value group needs a 6 character floor, otherwise the
    # "was" in these strings is treated as the password.
    masked, masked_str, err_str = SecretDetector.mask_secrets(false_positive_str)
    assert not masked
    assert err_str is None
    assert masked_str == false_positive_str


@pytest.mark.parametrize(
    "text,expected",
    [
        ("passcode: 123456", "passcode: ****"),
        ("otp=987654", "otp=****"),
        # The separator is captured and kept, as it is for every other pattern
        # in this module, so surrounding whitespace survives the substitution.
        ("pin = 4321", "pin = ****"),
        ("otac:5555", "otac:****"),
        # Quoted forms: the separator between the label and the digits includes
        # the quotes, which a `\s*[:=]\s*` separator could not cross.
        ('"passcode": "1234"', '"passcode": "****"'),
        ("'otp' : '9876'", "'otp' : '****'"),
        ('{"pin":"4321"}', '{"pin":"****"}'),
    ],
)
def test_mask_passcodes(text, expected):
    masked, masked_str, err_str = SecretDetector.mask_secrets(text)
    assert masked
    assert err_str is None
    assert masked_str == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("oauthClientId=myclientid123", "oauthClientId=****"),
        ("oauthClientSecret=abcdefgh12345", "oauthClientSecret=****"),
        ("clientSecret: someSecretValue", "clientSecret: ****"),
    ],
)
def test_mask_oauth_client_secrets(text, expected):
    masked, masked_str, err_str = SecretDetector.mask_secrets(text)
    assert masked
    assert err_str is None
    assert masked_str == expected


@pytest.mark.parametrize("token_name", ["access_token", "refresh_token"])
def test_mask_oauth_tokens(token_name):
    # Fixture data from JDBC's SecretDetectorTest.testMaskOAuthSecrets
    text = f'"{token_name}" : "some:FAKE_token123"'
    masked, masked_str, err_str = SecretDetector.mask_secrets(text)
    assert masked
    assert err_str is None
    assert masked_str == f'"{token_name}":"XXXX"'


def test_token_password():
    long_token = (
        "_Y1ZNETTn5/qfUWj3Jedby7gipDzQs=U"
        "KyJH9DS=nFzzWnfZKGV+C7GopWCGD4Lj"
        "OLLFZKOE26LXHDt3pTi4iI1qwKuSpf/F"
        "mClCMBSissVsU3Ei590FP0lPQQhcSGcD"
        "u69ZL_1X6e9h5z62t/iY7ZkII28n2qU="
        "nrBJUgPRCIbtJQkVJXIuOHjX4G5yUEKj"
        "ZBAx4w6=_lqtt67bIA=o7D=oUSjfywsR"
        "FoloNIkBPXCwFTv+1RVUHgVA2g8A9Lw5"
        "XdJYuI8vhg=f0bKSq7AhQ2Bh"
    )

    long_token2 = (
        "ktL57KJemuq4-M+Q0pdRjCIMcf1mzcr"
        "MwKteDS5DRE/Pb+5MzvWjDH7LFPV5b_"
        "/tX/yoLG3b4TuC6Q5qNzsARPPn_zs/j"
        "BbDOEg1-IfPpdsbwX6ETeEnhxkHIL4H"
        "sP-V"
    )

    random_pwd = "Fh[+2J~AcqeqW%?"
    random_pwd2 = random_pwd + "vdkav13"

    test_string_w_prefix = (
        "token=" + long_token + " random giberish " + "password:" + random_pwd
    )
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "token=****" + " random giberish " + "password:****"

    # order reversed
    test_string_w_prefix = (
        "password:" + random_pwd + " random giberish " + "token=" + long_token
    )

    masked, masked_str, err_str = SecretDetector.mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "password:****" + " random giberish " + "token=****"

    # multiple tokens and password
    test_string_w_prefix = (
        "token="
        + long_token
        + " random giberish "
        + "password:"
        + random_pwd
        + " random giberish "
        + "idToken:"
        + long_token2
    )
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert (
        masked_str
        == "token=****"
        + " random giberish "
        + "password:****"
        + " random giberish "
        + "idToken:****"
    )

    # multiple passwords
    test_string_w_prefix = (
        "password=" + random_pwd + " random giberish " + "pwd:" + random_pwd2
    )
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "password=" + "****" + " random giberish " + "pwd:" + "****"

    test_string_w_prefix = (
        "password="
        + random_pwd
        + " random giberish "
        + "password="
        + random_pwd2
        + " random giberish "
        + "password="
        + random_pwd
    )
    masked, masked_str, err_str = SecretDetector.mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert (
        masked_str
        == "password="
        + "****"
        + " random giberish "
        + "password="
        + "****"
        + " random giberish "
        + "password="
        + "****"
    )
