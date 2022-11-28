#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging

from .auth_by_plugin import AuthByPlugin
from .errorcode import ER_NO_PASSWORD
from .errors import ProgrammingError

logger = logging.getLogger(__name__)

MFA_TOKEN = "MFATOKEN"


class AuthByUsrPwdMfa(AuthByPlugin):
    """Username & password & mfa authenticator."""

    @property
    def assertion_content(self):
        return "*********"

    def __init__(self, password, mfa_token=None):
        """Initializes and instance with a password and a mfa token."""
        super().__init__()
        self._password = password
        self._mfa_token = mfa_token

    def set_mfa_token(self, value):
        self._mfa_token = value

    def authenticate(self, authenticator, service_name, account, user, password):
        """NOOP."""
        pass

    def update_body(self, body):
        """Sets the password and mfa_token if available.

        Don't set body['data']['AUTHENTICATOR'], since this is still snowflake default authenticator.
        """
        if not self._password:
            raise ProgrammingError(
                msg="Password for username password authenticator is empty.",
                errno=ER_NO_PASSWORD,
            )
        body["data"]["PASSWORD"] = self._password
        if self._mfa_token:
            body["data"]["TOKEN"] = self._mfa_token
