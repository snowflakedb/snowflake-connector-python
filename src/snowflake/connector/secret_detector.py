#!/usr/bin/env python
"""The secret detector detects sensitive information.

It masks secrets that might be leaked from two potential avenues
    1. Out of Band Telemetry
    2. Logging
"""
from __future__ import annotations

import logging
import os
import re
from typing import NamedTuple

MIN_TOKEN_LEN = os.getenv("MIN_TOKEN_LEN", 32)
MIN_PWD_LEN = os.getenv("MIN_PWD_LEN", 8)


class MaskedMessageData(NamedTuple):
    is_masked: bool = False
    masked_text: str | None = None
    error_str: str | None = None


class SecretDetector(logging.Formatter):
    AWS_KEY_PATTERN = re.compile(
        r"(aws_key_id|aws_secret_key|access_key_id|secret_access_key)\s*=\s*'([^']+)'",
        flags=re.IGNORECASE,
    )
    AWS_TOKEN_PATTERN = re.compile(
        r'(accessToken|tempToken|keySecret)"\s*:\s*"([a-z0-9/+]{32,}={0,2})"',
        flags=re.IGNORECASE,
    )
    SAS_TOKEN_PATTERN = re.compile(
        r"(sig|signature|AWSAccessKeyId|password|passcode)=(?P<secret>[a-z0-9%/+]{16,})",
        flags=re.IGNORECASE,
    )
    PRIVATE_KEY_PATTERN = re.compile(
        r"-{3,}BEGIN [A-Z ]*PRIVATE KEY-{3,}\n([\s\S]*?)\n-{3,}END [A-Z ]*PRIVATE KEY-{3,}",
        flags=re.MULTILINE | re.IGNORECASE,
    )
    PRIVATE_KEY_DATA_PATTERN = re.compile(
        r'"privateKeyData": "([a-z0-9/+=\\n]{10,})"', flags=re.MULTILINE | re.IGNORECASE
    )
    # Used for detecting OAuth tokens in serialized JSON
    OAUTH_TOKEN_PATTERN = re.compile(
        r'(access_token|refresh_token)"'
        r"\s*:\s*"
        r"\"([a-z0-9!\"#\$%&\\\'\(\)\*\+\,-\./:;<=>\?\@\[\]\^_`\{\|\}~]{3,})\"",
        flags=re.IGNORECASE,
    )
    # ':' and '%' belong in the value group so that tokens carrying extra detail
    # ahead of the token itself are still caught, e.g. token=ver:1-hint:1233-realToken
    CONNECTION_TOKEN_PATTERN = re.compile(
        r"(token|assertion content)" r"([\'\"\s:=]+)" r"([a-z0-9=/_\-\+\.:%]{8,})",
        flags=re.IGNORECASE,
    )

    # The {6,} floor keeps ordinary prose out of the mask, e.g. the "was" in
    # "no ID password was not given" would otherwise be treated as the value.
    PASSWORD_PATTERN = re.compile(
        r"(password"
        r"|pwd)"
        r"([\'\"\s:=]+)"
        r"([a-z0-9!\"#\$%&\\\'\(\)\*\+\,-\./:;<=>\?\@\[\]\^_`\{\|\}~]{6,})",
        flags=re.IGNORECASE,
    )

    # The separator class matches the other patterns in this file rather than
    # `\s*[:=]\s*`: a quoted value such as `"passcode": "1234"` puts a quote
    # between the label and the digits, and a separator that only accepts one
    # `:` or `=` cannot reach the value past it.
    PASSCODE_PATTERN = re.compile(
        r"(passcode|otp|pin|otac)" r"([\'\"\s:=]+)" r"([0-9]{4,6})",
        flags=re.IGNORECASE,
    )

    OAUTH_CLIENT_SECRET_PATTERN = re.compile(
        r"(oauthClientId|oauthClientSecret|clientSecret)"
        r"([\'\"\s:=]+)"
        r"([a-z0-9!\"#\$%&\\\'\(\)\*\+\,-\./:;<=>\?\@\[\]\^_`\{\|\}~]{8,})",
        flags=re.IGNORECASE,
    )

    SECRET_STARRED_MASK_STR = "****"

    @staticmethod
    def mask_connection_token(text: str) -> str:
        return SecretDetector.CONNECTION_TOKEN_PATTERN.sub(
            r"\1\2" + f"{SecretDetector.SECRET_STARRED_MASK_STR}", text
        )

    @staticmethod
    def mask_password(text: str) -> str:
        return SecretDetector.PASSWORD_PATTERN.sub(
            r"\1\2" + f"{SecretDetector.SECRET_STARRED_MASK_STR}", text
        )

    @staticmethod
    def mask_passcodes(text: str) -> str:
        return SecretDetector.PASSCODE_PATTERN.sub(
            r"\1\2" + f"{SecretDetector.SECRET_STARRED_MASK_STR}", text
        )

    @staticmethod
    def mask_oauth_client_secrets(text: str) -> str:
        return SecretDetector.OAUTH_CLIENT_SECRET_PATTERN.sub(
            r"\1\2" + f"{SecretDetector.SECRET_STARRED_MASK_STR}", text
        )

    @staticmethod
    def mask_aws_keys(text: str) -> str:
        return SecretDetector.AWS_KEY_PATTERN.sub(
            r"\1=" + f"'{SecretDetector.SECRET_STARRED_MASK_STR}'", text
        )

    @staticmethod
    def mask_sas_tokens(text: str) -> str:
        return SecretDetector.SAS_TOKEN_PATTERN.sub(
            r"\1=" + f"{SecretDetector.SECRET_STARRED_MASK_STR}", text
        )

    @staticmethod
    def mask_aws_tokens(text: str) -> str:
        return SecretDetector.AWS_TOKEN_PATTERN.sub(r'\1":"XXXX"', text)

    @staticmethod
    def mask_oauth_tokens(text: str) -> str:
        return SecretDetector.OAUTH_TOKEN_PATTERN.sub(r'\1":"XXXX"', text)

    @staticmethod
    def mask_private_key(text: str) -> str:
        return SecretDetector.PRIVATE_KEY_PATTERN.sub(
            "-----BEGIN PRIVATE KEY-----\\\\nXXXX\\\\n-----END PRIVATE KEY-----", text
        )

    @staticmethod
    def mask_private_key_data(text: str) -> str:
        return SecretDetector.PRIVATE_KEY_DATA_PATTERN.sub(
            '"privateKeyData": "XXXX"', text
        )

    @staticmethod
    def describe_value(value) -> str:
        """Non-sensitive metadata for a possibly-secret value (never the value).

        Lets call sites log present/empty/type/length for values that may be
        secrets (e.g. SSE-C chunk-header values, qrmk). SNOW-3675590.
        """
        if value is None:
            return "None"
        try:
            if isinstance(value, dict):
                if not value:
                    return "empty dict"
                inner = ", ".join(
                    f"{k}: {SecretDetector.describe_value(v)}" for k, v in value.items()
                )
                return f"dict{{{inner}}}"
            type_name = type(value).__name__
            length = len(value)
        except Exception:
            # describe_value must never raise (it runs while logging)
            return type(value).__name__
        if length == 0:
            return f"empty {type_name}"
        return f"{type_name} len={length}"

    @staticmethod
    def mask_secrets(text: str) -> MaskedMessageData:
        """Masks any secrets. This is the method that should be used by outside classes.

        Args:
            text: A string which may contain a secret.

        Returns:
            The masked string data in MaskedMessageData.
        """
        if text is None:
            return MaskedMessageData()

        masked = False
        err_str = None
        try:
            masked_text = SecretDetector.mask_connection_token(
                SecretDetector.mask_password(
                    SecretDetector.mask_oauth_client_secrets(
                        SecretDetector.mask_passcodes(
                            SecretDetector.mask_private_key_data(
                                SecretDetector.mask_private_key(
                                    SecretDetector.mask_oauth_tokens(
                                        SecretDetector.mask_aws_tokens(
                                            SecretDetector.mask_sas_tokens(
                                                SecretDetector.mask_aws_keys(text)
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
            if masked_text != text:
                masked = True
        except Exception as ex:
            # We'll assume that the exception was raised during masking
            # to be safe consider that the log has sensitive information
            # and do not raise an exception.
            masked = True
            masked_text = str(ex)
            err_str = str(ex)

        return MaskedMessageData(masked, masked_text, err_str)

    @staticmethod
    def create_formatting_error_log(
        original_record: logging.LogRecord, error_message: str
    ) -> str:
        return "{} - {} {} - {} - {} - {}".format(
            original_record.asctime,
            original_record.threadName,
            "secret_detector.py",
            "sanitize_log_str",
            original_record.levelname,
            error_message,
        )

    def format(self, record: logging.LogRecord) -> str:
        """Wrapper around logging module's formatter.

        This will ensure that the formatted message is free from sensitive credentials.

        Args:
            record: The logging record.

        Returns:
            Formatted desensitized log string.
        """
        try:
            unsanitized_log = super().format(record)
            masked, optional_sanitized_log, err_str = SecretDetector.mask_secrets(
                unsanitized_log
            )
            # Added to comply with type hints (Optional[str] is not accepted for str)
            sanitized_log = optional_sanitized_log or ""

            if masked and err_str is not None:
                sanitized_log = self.create_formatting_error_log(record, err_str)

        except Exception as ex:
            sanitized_log = self.create_formatting_error_log(
                record, "EXCEPTION - " + str(ex)
            )

        return sanitized_log
