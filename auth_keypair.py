#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import base64
import hashlib
from datetime import datetime, timedelta
from logging import getLogger

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key

from .auth_by_plugin import AuthByPlugin
from .errorcode import ER_INVALID_PRIVATE_KEY
from .errors import ProgrammingError
from .network import KEY_PAIR_AUTHENTICATOR

logger = getLogger(__name__)


class AuthByKeyPair(AuthByPlugin):
    """
        Key pair based authentication
    """
    LIFETIME = timedelta(seconds=120)
    ALGORITHM = 'RS256'
    ISSUER = 'iss'
    SUBJECT = 'sub'
    EXPIRE_TIME = 'exp'
    ISSUE_TIME = 'iat'

    def __init__(self, private_key):
        """
        :param private_key: a byte array of der formats of private key
        """
        self._private_key = private_key
        self._jwt_token = ''
        self._jwt_token_exp = 0

    def authenticate(
            self, authenticator, service_name, account, user, password):
        account = account.upper()
        user = user.upper()

        now = datetime.utcnow()

        try:
            private_key = load_der_private_key(data=self._private_key, password=None, backend=default_backend())
        except Exception as e:
            raise ProgrammingError(
                msg=u'Failed to load private key: {}\nPlease provide a valid unencrypted rsa private '
                    u'key in DER format as bytes object'.format(str(e)),
                errno=ER_INVALID_PRIVATE_KEY
            )

        if not isinstance(private_key, RSAPrivateKey):
            raise ProgrammingError(
                msg=u'Private key type ({}) not supported.\nPlease provide a valid rsa private '
                    u'key in DER format as bytes object'.format(private_key.__class__.__name__),
                errno=ER_INVALID_PRIVATE_KEY
            )

        public_key_fp = self.calculate_public_key_fingerprint(private_key)

        self._jwt_token_exp = now + self.LIFETIME
        payload = {
            self.ISSUER: "{}.{}.{}".format(account, user, public_key_fp),
            self.SUBJECT: "{}.{}".format(account, user),
            self.ISSUE_TIME: now,
            self.EXPIRE_TIME: self._jwt_token_exp
        }

        self._jwt_token = jwt.encode(payload, private_key,
                                     algorithm=self.ALGORITHM).decode('utf-8')

        return self._jwt_token

    @staticmethod
    def calculate_public_key_fingerprint(private_key):
        # get public key bytes
        public_key_der = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # take sha256 on raw bytes and then do base64 encode
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_der)

        public_key_fp = 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')
        logger.debug("Public key fingerprint is %s", public_key_fp)

        return public_key_fp

    def update_body(self, body):
        body[u'data'][u'AUTHENTICATOR'] = KEY_PAIR_AUTHENTICATOR
        body[u'data'][u'TOKEN'] = self._jwt_token

    def assertion_content(self):
        return self._jwt_token
