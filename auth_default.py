#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from .auth_by_plugin import AuthByPlugin


class AuthByDefault(AuthByPlugin):
    """
    Default username and password authenticator
    """

    @property
    def assertion_content(self):
        return "*********"

    def __init__(self, password):
        """
        Initializes an instance with a password
        """
        self._password = password

    def authenticate(
            self, authenticator, service_name, account, user, password):
        """
        NOP.
        """
        pass

    def update_body(self, body):
        """
        Set the password if available
        """
        if self._password:
            body[u'data'][u"PASSWORD"] = self._password
