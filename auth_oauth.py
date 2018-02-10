#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

from .auth import (
    AuthByExternalService,
    OAUTH_AUTHENTICATOR)


class AuthByOAuth(AuthByExternalService):
    """
    OAuth Based Authentication. Works by accepting an OAuth token and
    using that to authenticate.
    """

    @property
    def assertion_content(self):
        """ Returns the token."""
        return self._oauth_token

    def __init__(self, oauth_token):
        """
        Initializes an instance with an OAuth Token.
        """
        self._oauth_token = oauth_token

    def authenticate(self, authenticator, account, user, password):
        """
        Nothing to do here, token should be obtained outside of the driver.
        """
        pass

    def update_body(self, body):
        """
        OAuth needs the authenticator and token attributes set, as well as
        loginname, which is set already in auth.py ."""
        body[u'data'][u'AUTHENTICATOR'] = OAUTH_AUTHENTICATOR
        body[u'data'][u'TOKEN'] = self._oauth_token
