#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .auth_by_plugin import AuthByPlugin
from .network import ID_TOKEN_AUTHENTICATOR


class AuthByIdToken(AuthByPlugin):
    """Internal IdToken Based Authentication.

    Works by accepting an id_toke and use that to authenticate. Only be used when users are using EXTERNAL_BROWSER_AUTHENTICATOR
    """

    @property
    def assertion_content(self):
        return self._id_token

    def __init__(self, id_token):
        """Initialized an instance with an IdToken."""
        super().__init__()
        self._id_token = id_token

    def authenticate(self, authenticator, service_name, account, user, password):
        """Nothing to do here."""
        pass

    def update_body(self, body):
        """Idtoken needs the authenticator and token attributes set."""
        body["data"]["AUTHENTICATOR"] = ID_TOKEN_AUTHENTICATOR
        body["data"]["TOKEN"] = self._id_token
