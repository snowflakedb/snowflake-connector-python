#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .auth_by_plugin import AuthByPlugin
from .network import OAUTH_AUTHENTICATOR


class AuthByOAuth(AuthByPlugin):
    """OAuth Based Authentication.

    Works by accepting an OAuth token and using that to authenticate.
    """

    @property
    def assertion_content(self):
        """Returns the token."""
        return self._oauth_token

    def __init__(self, oauth_token):
        """Initializes an instance with an OAuth Token."""
        super().__init__()
        self._oauth_token = oauth_token

    def authenticate(self, authenticator, service_name, account, user, password):
        """Nothing to do here, token should be obtained outside of the driver."""
        pass

    def update_body(self, body):
        """Update some information required by OAuth.

        OAuth needs the authenticator and token attributes set, as well as loginname, which is set already in auth.py.
        """
        body["data"]["AUTHENTICATOR"] = OAUTH_AUTHENTICATOR
        body["data"]["TOKEN"] = self._oauth_token
