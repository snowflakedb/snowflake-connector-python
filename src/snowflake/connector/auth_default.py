#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from .auth_by_plugin import AuthByPlugin


class AuthByDefault(AuthByPlugin):
    """Default username and password authenticator."""

    @property
    def assertion_content(self):
        return "*********"

    def __init__(self, password):
        """Initializes an instance with a password."""
        self._password = password

    def authenticate(
            self, authenticator, service_name, account, user, password):
        """NOOP."""
        pass

    def update_body(self, body):
        """Sets the password if available."""
        if self._password:
            body['data']["PASSWORD"] = self._password
