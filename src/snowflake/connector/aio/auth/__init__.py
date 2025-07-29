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
from ._no_auth import AuthNoAuth
from ._oauth import AuthByOAuth
from ._okta import AuthByOkta
from ._pat import AuthByPAT
from ._usrpwdmfa import AuthByUsrPwdMfa
from ._webbrowser import AuthByWebBrowser
from ._workload_identity import AuthByWorkloadIdentity

FIRST_PARTY_AUTHENTICATORS = frozenset(
    (
        AuthByDefault,
        AuthByKeyPair,
        AuthByOAuth,
        AuthByOkta,
        AuthByUsrPwdMfa,
        AuthByWebBrowser,
        AuthByIdToken,
        AuthByPAT,
        AuthByWorkloadIdentity,
        AuthNoAuth,
    )
)

__all__ = [
    "AuthByPlugin",
    "AuthByDefault",
    "AuthByKeyPair",
    "AuthByPAT",
    "AuthByOAuth",
    "AuthByOkta",
    "AuthByUsrPwdMfa",
    "AuthByWebBrowser",
    "AuthByWorkloadIdentity",
    "AuthNoAuth",
    "Auth",
    "AuthType",
    "FIRST_PARTY_AUTHENTICATORS",
]
