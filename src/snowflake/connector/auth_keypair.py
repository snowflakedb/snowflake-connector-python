#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import base64
import hashlib
import os
from datetime import datetime, timedelta
from logging import getLogger
from typing import Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
)

from .auth_by_plugin import AuthByPlugin
from .errorcode import (
    ER_CONNECTION_TIMEOUT,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_INVALID_PRIVATE_KEY,
)
from .errors import OperationalError, ProgrammingError
from .network import KEY_PAIR_AUTHENTICATOR

logger = getLogger(__name__)


class AuthByKeyPair(AuthByPlugin):
    """Key pair based authentication."""

    ALGORITHM = "RS256"
    ISSUER = "iss"
    SUBJECT = "sub"
    EXPIRE_TIME = "exp"
    ISSUE_TIME = "iat"
    LIFETIME = 60
    DEFAULT_JWT_RETRY_ATTEMPTS = 10
    DEFAULT_JWT_CNXN_WAIT_TIME = 10

    def __init__(self, private_key, lifetime_in_seconds: int = LIFETIME):
        """Inits AuthByKeyPair class with private key.

        Args:
            private_key: a byte array of der formats of private key
            lifetime_in_seconds: number of seconds the JWT token will be valid
        """
        super().__init__()
        self._private_key = private_key
        self._jwt_token = ""
        self._jwt_token_exp = 0
        self._lifetime = timedelta(
            seconds=int(os.getenv("JWT_LIFETIME_IN_SECONDS", lifetime_in_seconds))
        )
        self._jwt_retry_attempts = int(
            os.getenv(
                "JWT_CNXN_RETRY_ATTEMPTS", AuthByKeyPair.DEFAULT_JWT_RETRY_ATTEMPTS
            )
        )
        self._jwt_cnxn_wait_time = timedelta(
            seconds=int(
                os.getenv(
                    "JWT_CNXN_WAIT_TIME", AuthByKeyPair.DEFAULT_JWT_CNXN_WAIT_TIME
                )
            )
        )
        self._current_retry_count = 0

    def authenticate(
        self,
        authenticator: str,
        service_name: Optional[str],
        account: str,
        user: str,
        password: Optional[str],
    ) -> str:
        if ".global" in account:
            account = account.partition("-")[0]
        else:
            account = account.partition(".")[0]
        account = account.upper()
        user = user.upper()

        now = datetime.utcnow()

        try:
            private_key = load_der_private_key(
                data=self._private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            raise ProgrammingError(
                msg="Failed to load private key: {}\nPlease provide a valid unencrypted rsa private "
                "key in DER format as bytes object".format(str(e)),
                errno=ER_INVALID_PRIVATE_KEY,
            )

        if not isinstance(private_key, RSAPrivateKey):
            raise ProgrammingError(
                msg="Private key type ({}) not supported.\nPlease provide a valid rsa private "
                "key in DER format as bytes object".format(
                    private_key.__class__.__name__
                ),
                errno=ER_INVALID_PRIVATE_KEY,
            )

        public_key_fp = self.calculate_public_key_fingerprint(private_key)

        self._jwt_token_exp = now + self._lifetime
        payload = {
            self.ISSUER: "{}.{}.{}".format(account, user, public_key_fp),
            self.SUBJECT: "{}.{}".format(account, user),
            self.ISSUE_TIME: now,
            self.EXPIRE_TIME: self._jwt_token_exp,
        }

        _jwt_token = jwt.encode(payload, private_key, algorithm=self.ALGORITHM)

        # jwt.encode() returns bytes in pyjwt 1.x and a string
        # in pyjwt 2.x
        if isinstance(_jwt_token, bytes):
            self._jwt_token = _jwt_token.decode("utf-8")
        else:
            self._jwt_token = _jwt_token

        return self._jwt_token

    @staticmethod
    def calculate_public_key_fingerprint(private_key):
        # get public key bytes
        public_key_der = private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        # take sha256 on raw bytes and then do base64 encode
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_der)

        public_key_fp = "SHA256:" + base64.b64encode(sha256hash.digest()).decode(
            "utf-8"
        )
        logger.debug("Public key fingerprint is %s", public_key_fp)

        return public_key_fp

    def update_body(self, body):
        body["data"]["AUTHENTICATOR"] = KEY_PAIR_AUTHENTICATOR
        body["data"]["TOKEN"] = self._jwt_token

    def assertion_content(self):
        return self._jwt_token

    def should_retry(self, count: int) -> bool:
        return count < self._jwt_retry_attempts

    def get_timeout(self) -> int:
        return self._jwt_cnxn_wait_time.seconds

    def handle_timeout(
        self,
        authenticator: str,
        service_name: Optional[str],
        account: str,
        user: str,
        password: Optional[str],
    ) -> None:
        if self._retry_ctx.get_current_retry_count() > self._jwt_retry_attempts:
            logger.debug("Exhausted max login attempts. Aborting connection")
            self._retry_ctx.reset()
            raise OperationalError(
                msg=f"Could not connect to Snowflake backend after {self._retry_ctx.get_current_retry_count()} attempt(s)."
                "Aborting",
                errno=ER_FAILED_TO_CONNECT_TO_DB,
            )
        else:
            logger.debug(
                f"Hit JWT timeout, attempt {self._retry_ctx.get_current_retry_count()}. Retrying..."
            )
            self._retry_ctx.increment_retry()

        self.authenticate(authenticator, service_name, account, user, password)

    def can_handle_exception(self, op: OperationalError) -> bool:
        if op.errno is ER_CONNECTION_TIMEOUT:
            return True
        return False
