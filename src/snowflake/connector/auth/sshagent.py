#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import hashlib
import os
import struct
from datetime import datetime, timedelta, timezone
from logging import getLogger
from typing import Any

import jwt
import paramiko
from jwt import algorithms as jwt_algorithms

from ..errorcode import ER_CONNECTION_TIMEOUT, ER_INVALID_PRIVATE_KEY, ER_KEY_NAME_NOT_FOUND
from ..errors import OperationalError, ProgrammingError
from ..network import KEY_PAIR_AUTHENTICATOR
from .by_plugin import AuthByPlugin, AuthType

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = getLogger(__name__)


class RSASSHAlgorithm(jwt_algorithms.RSAAlgorithm):
    def sign(self, msg: bytes, key_name: str) -> bytes:
        agent = paramiko.Agent()
        all_keys = agent.get_keys()
        found_key = None
        for key in all_keys:
            if key.comment == key_name:
                found_key = key
                break

        if found_key is None:
            raise ProgrammingError(
                msg=f"Failed to find key {key_name} in agent",
                errno=ER_KEY_NAME_NOT_FOUND,
            )

        # ssh_signature is in the format [unsigned int for length of block][data block]...
        # first field is the signature type and the second field is the signed data chunk.
        ssh_signature = found_key.sign_ssh_data(msg, "rsa-sha2-256")
        pos = 0
        # read length
        length = struct.unpack(">I", ssh_signature[pos:pos + 4])[0]
        # advance past length field
        pos += 4
        # advance past text of signature type
        pos += length
        # advance past next length field
        pos += 4
        # read the rest of the payload as signature
        return ssh_signature[pos:]

    def prepare_key(self, key: str) -> str:
        return key


class AuthBySSHAgent(AuthByPlugin):
    """SSH Agent based authentication."""

    ALGORITHM = "RS256"
    ISSUER = "iss"
    SUBJECT = "sub"
    EXPIRE_TIME = "exp"
    ISSUE_TIME = "iat"
    LIFETIME = 60
    DEFAULT_JWT_RETRY_ATTEMPTS = 10
    DEFAULT_JWT_CNXN_WAIT_TIME = 10

    def __init__(
        self,
        key_name: str,
        lifetime_in_seconds: int = LIFETIME,
        **kwargs,
    ) -> None:
        """Inits AuthBySSHAgent class with SSH Agent key name.

        Args:
            key_name: string of the key pair name from the ssh-agent to use
            lifetime_in_seconds: number of seconds the JWT token will be valid
        """
        super().__init__(
            max_retry_attempts=int(
                os.getenv(
                    "JWT_CNXN_RETRY_ATTEMPTS", AuthBySSHAgent.DEFAULT_JWT_RETRY_ATTEMPTS
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
                        AuthBySSHAgent.DEFAULT_JWT_CNXN_WAIT_TIME,
                    )
                )
            ).total_seconds()
        )

        self._key_name: str | None = key_name
        self._jwt_token = ""
        self._jwt_token_exp = 0
        self._lifetime = timedelta(
            seconds=int(os.getenv("JWT_LIFETIME_IN_SECONDS", lifetime_in_seconds))
        )

    def reset_secrets(self) -> None:
        # doesn't contain any secrets
        return

    @property
    def type_(self) -> AuthType:
        return AuthType.KEY_PAIR_SSH

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

        key_name = self._ssh_key_name

        public_key_fp, public_key = self.get_public_key_and_fingerprint(key_name)

        self._jwt_token_exp = now + self._lifetime
        payload = {
            self.ISSUER: f"{account}.{user}.{public_key_fp}",
            self.SUBJECT: f"{account}.{user}",
            self.ISSUE_TIME: now,
            self.EXPIRE_TIME: self._jwt_token_exp,
        }
        jwt.unregister_algorithm(self.ALGORITHM)
        jwt.register_algorithm(self.ALGORITHM, RSASSHAlgorithm(self.ALGORITHM))

        _jwt_token = jwt.encode(payload, key_name, algorithm=self.ALGORITHM)

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
    def get_public_key_and_fingerprint(key_name):
        # get public key bytes
        agent = paramiko.Agent()
        all_keys = agent.get_keys()
        found_key = None
        for key in all_keys:
            if key.comment == key_name:
                found_key = key
                break

        if found_key is None:
            raise ProgrammingError(
                msg=f"Failed to find key {key_name} in agent",
                errno=ER_KEY_NAME_NOT_FOUND,
            )

        if found_key.algorithm_name != "RSA":
            raise ProgrammingError(
                msg=f"Unsupported key type {found_key.algorithm_name}",
                errno=ER_INVALID_PRIVATE_KEY,
            )

        # Need to convert from SSH fingerprint to RSA fingerprint
        base64_key = found_key.get_base64()
        rsa_base64_key = f"ssh-rsa {base64_key}"
        decoded_key = serialization.load_ssh_public_key(rsa_base64_key.encode("utf-8"), default_backend())
        der_bytes = decoded_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint_sha256 = hashlib.sha256()
        fingerprint_sha256.update(der_bytes)
        fingerprint = fingerprint_sha256.digest()
        b64_fp = base64.b64encode(fingerprint).decode("utf-8")

        public_key_fp = f"SHA256:{b64_fp}"
        public_key = found_key.get_base64()
        logger.debug("Public key fingerprint is %s", public_key_fp)

        return public_key_fp, public_key

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
