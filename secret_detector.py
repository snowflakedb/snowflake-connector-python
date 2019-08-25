#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
"""
Detects and Masks Secrets. Based on SecretDetector.java in the JDBC Driver
"""

import re


class SecretDetector(object):

    AWS_KEY_PATTERN = re.compile(r"(aws_key_id|aws_secret_key|access_key_id|secret_access_key)\s*=\s*'([^']+)'", flags=re.IGNORECASE)
    AWS_TOKEN_PATTERN = re.compile(r'(accessToken|tempToken|keySecret)"\s*:\s*"([a-z0-9/+]{32,}={0,2})"', flags=re.IGNORECASE)
    SAS_TOKEN_PATTERN = re.compile(r'(sig|signature|AWSAccessKeyId|password|passcode)=(?P<secret>[a-z0-9%/+]{16,})', flags=re.IGNORECASE)
    PRIVATE_KEY_PATTERN = re.compile(r'-----BEGIN PRIVATE KEY-----\\n([a-z0-9/+=\\n]{32,})\\n-----END PRIVATE KEY-----', flags=re.MULTILINE | re.IGNORECASE)
    PRIVATE_KEY_DATA_PATTERN = re.compile(r'"privateKeyData": "([a-z0-9/+=\\n]{10,})"', flags=re.MULTILINE | re.IGNORECASE)

    @staticmethod
    def mask_aws_keys(text):
        return SecretDetector.AWS_KEY_PATTERN.sub(r"\1='**********'", text)

    @staticmethod
    def mask_sas_tokens(text):
        return SecretDetector.SAS_TOKEN_PATTERN.sub(r'\1=**********', text)

    @staticmethod
    def mask_aws_tokens(text):
        return SecretDetector.AWS_TOKEN_PATTERN.sub(r'\1":"XXXX"', text)

    @staticmethod
    def mask_private_key(text):
        return SecretDetector.PRIVATE_KEY_PATTERN.sub("-----BEGIN PRIVATE KEY-----\\\\nXXXX\\\\n-----END PRIVATE KEY-----", text)

    @staticmethod
    def mask_private_key_data(text):
        return SecretDetector.PRIVATE_KEY_DATA_PATTERN.sub('"privateKeyData": "XXXX"', text)

    @staticmethod
    def mask_secrets(text):
        """
        Masks any secrets. This is the method that should be used by outside classes

        :param text: a string which may contain a secret
        :return: the masked string
        """
        if text is None:
            return None

        masked_text = SecretDetector.mask_private_key_data(
            SecretDetector.mask_private_key(
                SecretDetector.mask_aws_tokens(
                    SecretDetector.mask_sas_tokens(
                        SecretDetector.mask_aws_keys(
                            text
                        )
                    )
                )
            )
        )
        return masked_text
