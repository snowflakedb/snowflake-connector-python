#!/usr/bin/env python
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
from logging import getLogger
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
)

from ..errorcode import ER_CONNECTION_TIMEOUT, ER_INVALID_PRIVATE_KEY
from ..errors import OperationalError, ProgrammingError
from ..network import KEY_PAIR_AUTHENTICATOR
from .by_plugin import AuthByPlugin, AuthType

logger = getLogger(__name__)


class AuthByKeyPair(AuthByPlugin):
    """Key pair based authentication."""

    ALG_RS256 = "RS256"
    ALG_ES256 = "ES256"
    ALG_ES384 = "ES384"
    ALG_ES512 = "ES512"

    ISSUER = "iss"
    SUBJECT = "sub"
    EXPIRE_TIME = "exp"
    ISSUE_TIME = "iat"
    LIFETIME = 60
    DEFAULT_JWT_RETRY_ATTEMPTS = 10
    DEFAULT_JWT_CNXN_WAIT_TIME = 10

    def __init__(
        self,
        private_key: bytes | str | RSAPrivateKey | EllipticCurvePrivateKey,
        private_key_passphrase: bytes | None = None,
        lifetime_in_seconds: int = LIFETIME,
        **kwargs,
    ) -> None:
        """Inits AuthByKeyPair class with private key.

        Args:
            private_key: a byte array of der formats of private key, or an
                object that implements the `RSAPrivateKey` or `EllipticCurvePrivateKey` interface.
            lifetime_in_seconds: number of seconds the JWT token will be valid
        """
        super().__init__(
            max_retry_attempts=int(
                os.getenv(
                    "JWT_CNXN_RETRY_ATTEMPTS", AuthByKeyPair.DEFAULT_JWT_RETRY_ATTEMPTS
                )
            ),
            **kwargs,
        )

        # set internal socket timeout override
        self._socket_timeout = int(
            timedelta(
                seconds=int(
                    os.getenv(
                        "JWT_CNXN_WAIT_TIME",
                        AuthByKeyPair.DEFAULT_JWT_CNXN_WAIT_TIME,
                    )
                )
            ).total_seconds()
        )

        self._private_key: bytes | str | RSAPrivateKey | EllipticCurvePrivateKey | None = private_key
        self._private_key_passphrase: bytes | None = private_key_passphrase
        self._jwt_token = ""
        self._jwt_token_exp = 0
        self._lifetime = timedelta(
            seconds=int(os.getenv("JWT_LIFETIME_IN_SECONDS", lifetime_in_seconds))
        )

    def reset_secrets(self) -> None:
        self._private_key = None

    @property
    def type_(self) -> AuthType:
        return AuthType.KEY_PAIR

    def prepare(
        self,
        *,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> str:
        if ".global" in account:
            account = account.partition("-")[0]
        else:
            account = account.partition(".")[0]
        account = account.upper()
        user = user.upper()

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if isinstance(self._private_key, str):
            try:
                self._private_key = base64.b64decode(self._private_key)
            except Exception as e:
                raise ProgrammingError(
                    msg=f"Failed to decode private key: {e}\nPlease provide a valid "
                    "unencrypted RSA or ECDSA private key in base64-encoded DER format as a "
                    "str object",
                    errno=ER_INVALID_PRIVATE_KEY,
                )

        if isinstance(self._private_key, bytes):
            try:
                private_key = load_der_private_key(
                    data=self._private_key,
                    password=self._private_key_passphrase,
                    backend=default_backend(),
                )
            except Exception as e:
                raise ProgrammingError(
                    msg=f"Failed to load private key: {e}\nPlease provide a valid "
                    "RSA or ECDSA private key in DER format as bytes object. If the key is "
                    "encrypted, provide the passphrase via private_key_passphrase",
                    errno=ER_INVALID_PRIVATE_KEY,
                )

            if not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
                raise ProgrammingError(
                    msg=f"Private key type ({private_key.__class__.__name__}) not supported."
                    "\nPlease provide a valid RSA or ECDSA private key in DER format as bytes "
                    "object",
                    errno=ER_INVALID_PRIVATE_KEY,
                )
        elif isinstance(self._private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
            private_key = self._private_key
        else:
            raise TypeError(
                f"Expected bytes, RSAPrivateKey, or EllipticCurvePrivateKey, got {type(self._private_key)}"
            )

        public_key_fp = self.calculate_public_key_fingerprint(private_key)

        self._jwt_token_exp = now + self._lifetime
        payload = {
            self.ISSUER: f"{account}.{user}.{public_key_fp}",
            self.SUBJECT: f"{account}.{user}",
            self.ISSUE_TIME: now,
            self.EXPIRE_TIME: self._jwt_token_exp,
        }

        # select algorithm based on key type and curve
        if isinstance(private_key, EllipticCurvePrivateKey):
            curve = private_key.curve
            if isinstance(curve, SECP256R1):
                algorithm = self.ALG_ES256
            elif isinstance(curve, SECP384R1):
                algorithm = self.ALG_ES384
            elif isinstance(curve, SECP521R1):
                algorithm = self.ALG_ES512
            else:
                raise ProgrammingError(
                    msg=f"Unsupported EC curve: {curve.name}. Supported: SECP256R1, SECP384R1, SECP521R1",
                    errno=ER_INVALID_PRIVATE_KEY,
                )
        else:
            algorithm = self.ALG_RS256

        _jwt_token = jwt.encode(payload, private_key, algorithm=algorithm)

        # jwt.encode() returns bytes in pyjwt 1.x and a string
        # in pyjwt 2.x
        if isinstance(_jwt_token, bytes):
            self._jwt_token = _jwt_token.decode("utf-8")
        else:
            self._jwt_token = _jwt_token

        return self._jwt_token

    def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return {"success": False}

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

    def update_body(self, body: dict[Any, Any]) -> None:
        body["data"]["AUTHENTICATOR"] = KEY_PAIR_AUTHENTICATOR
        body["data"]["TOKEN"] = self._jwt_token

    def assertion_content(self) -> str:
        return self._jwt_token

    def should_retry(self, count: int) -> bool:
        return count < self._jwt_retry_attempts

    def handle_timeout(
        self,
        *,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
        **kwargs: Any,
    ) -> None:
        logger.debug("Invoking base timeout handler")
        super().handle_timeout(
            authenticator=authenticator,
            service_name=service_name,
            account=account,
            user=user,
            password=password,
            delete_params=False,
        )

        logger.debug("Base timeout handler passed, preparing new token before retrying")
        self.prepare(account=account, user=user)

    @staticmethod
    def can_handle_exception(op: OperationalError) -> bool:
        if op.errno is ER_CONNECTION_TIMEOUT:
            return True
        return False
