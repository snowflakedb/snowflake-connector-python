from __future__ import annotations

from ._auth import Auth, get_public_key_fingerprint, get_token_from_private_key
from .by_plugin import AuthByPlugin, AuthType
from .default import AuthByDefault
from .idtoken import AuthByIdToken
from .keypair import AuthByKeyPair
from .no_auth import AuthNoAuth
from .oauth import AuthByOAuth
from .okta import AuthByOkta
from .pat import AuthByPAT
from .usrpwdmfa import AuthByUsrPwdMfa
from .webbrowser import AuthByWebBrowser
from .workload_identity import AuthByWorkloadIdentity

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
    "get_public_key_fingerprint",
    "get_token_from_private_key",
]
