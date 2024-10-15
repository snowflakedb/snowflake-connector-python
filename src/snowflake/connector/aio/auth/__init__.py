#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from ...auth.by_plugin import AuthType
from ._auth import Auth
from ._by_plugin import AuthByPlugin
from ._default import AuthByDefault
from ._idtoken import AuthByIdToken
from ._keypair import AuthByKeyPair
from ._oauth import AuthByOAuth
from ._okta import AuthByOkta
from ._usrpwdmfa import AuthByUsrPwdMfa
from ._webbrowser import AuthByWebBrowser

FIRST_PARTY_AUTHENTICATORS = frozenset(
    (
        AuthByDefault,
        AuthByKeyPair,
        AuthByOAuth,
        AuthByOkta,
        AuthByUsrPwdMfa,
        AuthByWebBrowser,
        AuthByIdToken,
    )
)

__all__ = [
    "AuthByPlugin",
    "AuthByDefault",
    "AuthByKeyPair",
    "AuthByOAuth",
    "AuthByOkta",
    "AuthByUsrPwdMfa",
    "AuthByWebBrowser",
    "Auth",
    "AuthType",
    "FIRST_PARTY_AUTHENTICATORS",
]
