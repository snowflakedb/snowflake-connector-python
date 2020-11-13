#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging

from .auth_by_plugin import AuthByPlugin
from .network import USR_PWD_MFA_AUTHENTICATOR

logger = logging.getLogger(__name__)

MFA_TOKEN = 'MFATOKEN'


class AuthByUsrPwdMfa(AuthByPlugin):
    """Username & password & mfa authenticator."""

    @property
    def assertion_content(self):
        return "*********"

    def __init__(self, password, mfa_token=None):
        """Initializes and instance with a password and a mfa token."""
        self._password = password
        self.mfa_token = mfa_token

    @property
    def mfa_token(self):
        return self._mfa_token

    @mfa_token.setter
    def mfa_token(self, value):
        self._mfa_token = value

    def authenticate(
            self, authenticator, service_name, account, user, password):
        """NOOP."""
        pass

    def update_body(self, body):
        """Sets the password and mfa_token if available."""
        body['data']['AUTHENTICATOR'] = USR_PWD_MFA_AUTHENTICATOR
        if self._password:
            body['data']['PASSWORD'] = self._password
        if self._mfa_token:
            body['data']['TOKEN'] = self._mfa_token
