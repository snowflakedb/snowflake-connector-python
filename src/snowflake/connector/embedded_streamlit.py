#!/usr/bin/env python
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .errorcode import ER_FAILED_TO_REQUEST, ER_INVALID_VALUE, ER_NO_HOSTNAME_FOUND
from .errors import ProgrammingError
from .session_manager import SessionManager, SessionManagerFactory

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    from .connection import SnowflakeConnection

logger = logging.getLogger(__name__)

# OAuth 2.0 token-exchange grant (RFC 8693).
_GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

# subject_token_type URNs, verified against GlobalServices SFOAuthTokenType.java
# (modules/dbsec/authn-api), 2026-06-25.
SUBJECT_TOKEN_TYPE_SESSION = "urn:snowflake:token-type:session"
SUBJECT_TOKEN_TYPE_PAT = "programmatic_access_token"
SUBJECT_TOKEN_TYPE_WIF = "urn:snowflake:token-type:wif"
SUBJECT_TOKEN_TYPE_OAUTH_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
# PROVISIONAL: there is no key-pair-JWT subject_token_type in the GS enum today. This
# default is used for the key_pair credential mode and is overridable via prepare(
# subject_token_type=...) pending the GS keypair extension.
SUBJECT_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

# Embed URL query parameters reproduced from the GS system function
# StreamlitGenerateEmbedUrl.java.
_PARAM_PARENT_ORIGIN = "__parentOrigin"
_PARAM_EMBEDDED_APP = "__embeddedApp"


class EmbeddedStreamlit:
    """Generate a Streamlit embed URL via the OAuth token-exchange endpoint.

    This is the native equivalent of the ``SYSTEM$STREAMLIT_GENERATE_EMBED_URL``
    SQL system function. It lets a customer backend mint a short-lived, single-use
    embed URL for a Streamlit-in-Snowflake app from a service credential (PAT,
    key-pair, or a live session) without issuing SQL.

    Usage::

        from snowflake.connector import EmbeddedStreamlit

        url = (
            EmbeddedStreamlit("MYDB.MYSCHEMA.MY_APP", "https://analytics.example.com")
            .prepare(pat="<pat>", account="myaccount")
            .get_embed_url()
        )

    Exactly one primary credential source must be supplied to :meth:`prepare`:
    ``pat``, ``conn``, ``key_pair``, or an explicit ``subject_token``.
    """

    def __init__(self, streamlit_id: str, parent_origin: str) -> None:
        """Init EmbeddedStreamlit.

        Args:
            streamlit_id: Fully-qualified name of the Streamlit app
                (``db.schema.app``). Must not contain a ``:`` since it becomes
                part of the token-exchange scope ``session:streamlit:<fqn>``.
            parent_origin: The origin (scheme://host[:port]) of the 3rd-party page
                that embeds the app. Carried back as the ``__parentOrigin`` query
                parameter of the final embed URL.
        """
        if not streamlit_id:
            raise ProgrammingError(
                msg="streamlit_id must be a non-empty string",
                errno=ER_INVALID_VALUE,
            )
        if ":" in streamlit_id:
            raise ProgrammingError(
                msg="streamlit_id (the db.schema.app FQN) must not contain ':'",
                errno=ER_INVALID_VALUE,
            )
        if not parent_origin:
            raise ProgrammingError(
                msg="parent_origin must be a non-empty string",
                errno=ER_INVALID_VALUE,
            )

        self._streamlit_id = streamlit_id
        self._parent_origin = parent_origin

        # Populated by prepare().
        self._embed_url: str | None = None
        self._expires_in: int | None = None

    def prepare(
        self,
        *,
        pat: str | None = None,
        conn: SnowflakeConnection | None = None,
        key_pair: bytes | str | RSAPrivateKey | EllipticCurvePrivateKey | None = None,
        account: str | None = None,
        host: str | None = None,
        user: str | None = None,
        subject_token: str | None = None,
        subject_token_type: str | None = None,
        token_endpoint: str | None = None,
        session_manager: SessionManager | None = None,
        timeout: int | None = 30,
    ) -> EmbeddedStreamlit:
        """Exchange the service credential for an authorization code and build the URL.

        Exactly one primary credential source must be given: ``pat``, ``conn``,
        ``key_pair``, or an explicit ``subject_token``.

        Args:
            pat: A Programmatic Access Token value. Requires ``account`` (or
                ``host``) so the token endpoint can be resolved.
            conn: A live :class:`SnowflakeConnection`. The session token and host
                are pulled from it; no ``account``/``host`` needed.
            key_pair: An unencrypted RSA/ECDSA private key (DER bytes, base64 str,
                or a loaded key object). Requires ``account`` and ``user`` to mint
                the key-pair JWT. May also be a pre-signed JWT string when paired
                with an explicit ``subject_token_type``.
            account: Snowflake account identifier; used to build the host when
                ``host`` is not given, and to mint the key-pair JWT.
            host: Explicit host (e.g. ``myaccount.snowflakecomputing.com``).
                Overrides ``account`` for host resolution.
            user: Snowflake user; required for the ``key_pair`` mode JWT.
            subject_token: A pre-obtained credential value to send as-is. Pair with
                ``subject_token_type`` for forward-compatibility / escape hatch.
            subject_token_type: Override the ``subject_token_type`` URN. Defaults are
                chosen per credential mode (session/PAT/JWT). Required when only
                ``subject_token`` is given.
            token_endpoint: Override the full token endpoint URL. Defaults to
                ``https://<host>/oauth/token``. Injectable for tests.
            session_manager: Override the HTTP session manager (injectable for
                tests). Defaults to the connection's manager (``conn`` mode) or a
                freshly created one.
            timeout: Per-request timeout in seconds for the token exchange POST.

        Returns:
            self, so :meth:`get_embed_url` can be chained.
        """
        subject_token_value, token_type, resolved_host, resolved_manager = (
            self._resolve_credential(
                pat=pat,
                conn=conn,
                key_pair=key_pair,
                account=account,
                host=host,
                user=user,
                subject_token=subject_token,
                subject_token_type=subject_token_type,
                session_manager=session_manager,
            )
        )

        endpoint = token_endpoint or self._default_token_endpoint(resolved_host)
        if not endpoint:
            raise ProgrammingError(
                msg="Unable to resolve the token endpoint: provide one of "
                "token_endpoint, host, account, or conn.",
                errno=ER_NO_HOSTNAME_FOUND,
            )

        redirect_uri, expires_in = self._exchange_token(
            endpoint=endpoint,
            subject_token=subject_token_value,
            subject_token_type=token_type,
            session_manager=resolved_manager,
            timeout=timeout,
        )

        self._embed_url = self._build_embed_url(redirect_uri)
        self._expires_in = expires_in
        return self

    def _resolve_credential(
        self,
        *,
        pat: str | None,
        conn: SnowflakeConnection | None,
        key_pair: bytes | str | RSAPrivateKey | EllipticCurvePrivateKey | None,
        account: str | None,
        host: str | None,
        user: str | None,
        subject_token: str | None,
        subject_token_type: str | None,
        session_manager: SessionManager | None,
    ) -> tuple[str, str, str | None, SessionManager]:
        """Validate inputs and produce (subject_token, subject_token_type, host, mgr).

        Enforces exactly-one primary credential source and derives the matching
        ``subject_token_type`` URN unless the caller overrides it.
        """
        sources = {
            "pat": pat is not None,
            "conn": conn is not None,
            "key_pair": key_pair is not None,
            "subject_token": subject_token is not None,
        }
        chosen = [name for name, present in sources.items() if present]
        if len(chosen) == 0:
            raise ProgrammingError(
                msg="A credential is required: pass exactly one of pat, conn, "
                "key_pair, or subject_token.",
                errno=ER_INVALID_VALUE,
            )
        if len(chosen) > 1:
            raise ProgrammingError(
                msg="Exactly one credential source is allowed, got: "
                + ", ".join(sorted(chosen)),
                errno=ER_INVALID_VALUE,
            )

        resolved_host = host
        resolved_manager = session_manager

        if pat is not None:
            token_value = pat
            token_type = subject_token_type or SUBJECT_TOKEN_TYPE_PAT
        elif conn is not None:
            token_value = self._session_token_from_conn(conn)
            token_type = subject_token_type or SUBJECT_TOKEN_TYPE_SESSION
            if resolved_host is None:
                resolved_host = getattr(conn, "host", None)
            if resolved_manager is None:
                # Reuse the connection's pooled session manager when available.
                resolved_manager = getattr(conn, "_session_manager", None)
        elif key_pair is not None:
            token_value = self._jwt_from_key_pair(key_pair, account, user)
            # PROVISIONAL default — overridable pending the GS keypair extension.
            token_type = subject_token_type or SUBJECT_TOKEN_TYPE_JWT
        else:
            # Explicit subject_token escape hatch.
            token_value = subject_token
            if not subject_token_type:
                raise ProgrammingError(
                    msg="subject_token_type is required when passing an explicit "
                    "subject_token.",
                    errno=ER_INVALID_VALUE,
                )
            token_type = subject_token_type

        if not token_value:
            raise ProgrammingError(
                msg="Resolved credential value is empty.",
                errno=ER_INVALID_VALUE,
            )

        if resolved_host is None and host is None and account is not None:
            resolved_host = self._host_from_account(account)

        if resolved_manager is None:
            resolved_manager = SessionManagerFactory.get_manager()

        return token_value, token_type, resolved_host, resolved_manager

    @staticmethod
    def _session_token_from_conn(conn: SnowflakeConnection) -> str:
        """Pull the live session token out of a SnowflakeConnection.

        The session token lives on the REST layer (``conn.rest.token``). We never
        log its value.
        """
        rest = getattr(conn, "rest", None)
        token = getattr(rest, "token", None) if rest is not None else None
        if not token:
            raise ProgrammingError(
                msg="The provided connection has no active session token; ensure it "
                "is connected before calling prepare(conn=...).",
                errno=ER_INVALID_VALUE,
            )
        return token

    @staticmethod
    def _jwt_from_key_pair(
        key_pair: bytes | str | RSAPrivateKey | EllipticCurvePrivateKey,
        account: str | None,
        user: str | None,
    ) -> str:
        """Mint a key-pair JWT, or pass through a pre-signed JWT string.

        When ``account`` and ``user`` are supplied, ``key_pair`` is treated as a
        private key and signed via :class:`AuthByKeyPair`. When they are absent,
        ``key_pair`` must already be a signed JWT string and is used verbatim.
        """
        if account and user:
            # Local import to avoid pulling auth (and pyjwt) at module import time.
            from .auth.keypair import AuthByKeyPair

            auth = AuthByKeyPair(private_key=key_pair)
            return auth.prepare(account=account, user=user)
        if isinstance(key_pair, str):
            # Pre-signed JWT passed directly.
            return key_pair
        raise ProgrammingError(
            msg="key_pair mode requires both account and user to mint a JWT, or a "
            "pre-signed JWT string.",
            errno=ER_INVALID_VALUE,
        )

    @staticmethod
    def _host_from_account(account: str) -> str:
        # Local import keeps the module import lightweight.
        from .util_text import construct_hostname

        return construct_hostname(None, account)

    @staticmethod
    def _default_token_endpoint(host: str | None) -> str | None:
        if not host:
            return None
        return f"https://{host}/oauth/token"

    def _scope(self) -> str:
        return f"session:streamlit:{self._streamlit_id}"

    def _exchange_token(
        self,
        *,
        endpoint: str,
        subject_token: str,
        subject_token_type: str,
        session_manager: SessionManager,
        timeout: int | None,
    ) -> tuple[str, int | None]:
        """POST the token-exchange request and return (redirect_uri, expires_in).

        The request body is form-urlencoded per the wire contract. The credential
        value (``subject_token``) is treated as a secret and never logged.
        """
        body = {
            "grant_type": _GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "scope": self._scope(),
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json",
        }

        logger.debug(
            "Requesting Streamlit embed token exchange: endpoint=%s, scope=%s, "
            "subject_token_type=%s",
            endpoint,
            self._scope(),
            subject_token_type,
        )

        response = session_manager.post(
            endpoint,
            headers=headers,
            data=urlencode(body),
            timeout=timeout,
        )

        if response.status_code != 200:
            # Never echo the response body; it could contain sensitive material.
            raise ProgrammingError(
                msg="Streamlit embed token exchange failed with HTTP status "
                f"{response.status_code}.",
                errno=ER_FAILED_TO_REQUEST,
            )

        try:
            payload = response.json()
        except Exception as exc:
            raise ProgrammingError(
                msg=f"Streamlit embed token exchange returned a non-JSON response: {exc}",
                errno=ER_FAILED_TO_REQUEST,
            )

        redirect_uri = (
            payload.get("redirect_uri") if isinstance(payload, dict) else None
        )
        if not redirect_uri:
            raise ProgrammingError(
                msg="Streamlit embed token exchange response is missing 'redirect_uri'.",
                errno=ER_FAILED_TO_REQUEST,
            )

        expires_in = payload.get("expires_in") if isinstance(payload, dict) else None
        return redirect_uri, self._coerce_expires_in(expires_in)

    @staticmethod
    def _coerce_expires_in(value: object) -> int | None:
        """Coerce the server's ``expires_in`` to ``int | None``.

        The wire contract documents an integer, but defend against a server that
        returns it as a JSON string (or any non-int) so the ``expires_in``
        property keeps its declared ``int | None`` type for callers that do
        ``ttl = es.expires_in``.
        """
        if isinstance(value, bool):
            # bool is an int subclass; do not treat True/False as a TTL.
            return None
        if isinstance(value, int):
            return value
        try:
            return int(value)  # handles int-like floats and numeric strings
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_code(redirect_uri: str) -> str:
        """Extract the single-use authorization code from the redirect URI.

        Per the wire contract the code may be carried as a URL fragment
        (``#code=...``) OR query (``?code=...`` / ``&code=...``). Fragment takes
        precedence. The code value is treated as a secret and never logged.

        The code is read VERBATIM and is NOT form-decoded: the GS system function
        emits it via ``URIBuilder.setFragment("code=" + azCode)``, which does not
        percent-encode the fragment, and authorization codes are commonly
        base64/base64url and may contain ``+``, ``/``, and ``=``. Form-decoding
        (e.g. ``urllib.parse.parse_qsl``) would turn a literal ``+`` into a space
        and corrupt the single-use code, so we split on the literal ``code=``
        delimiter and take the raw value up to the next ``&`` instead.
        """
        parts = urlsplit(redirect_uri)

        # Fragment first, then query — read the raw value (no form-decoding).
        for carrier in (parts.fragment, parts.query):
            code = EmbeddedStreamlit._raw_code_value(carrier)
            if code:
                return code

        raise ProgrammingError(
            msg="Could not find authorization code in token-exchange redirect_uri.",
            errno=ER_INVALID_VALUE,
        )

    @staticmethod
    def _raw_code_value(carrier: str) -> str | None:
        """Return the verbatim ``code`` value from a ``&``-separated carrier.

        ``carrier`` is a raw fragment or query string. We split only on the
        ``&`` separator and the first ``=`` of each segment, so the value is
        returned byte-for-byte (no ``+`` -> space, no percent-decoding).
        """
        if not carrier:
            return None
        for segment in carrier.split("&"):
            key, sep, value = segment.partition("=")
            if key == "code" and sep and value:
                return value
        return None

    def _build_embed_url(self, redirect_uri: str) -> str:
        """Assemble the final embed URL from the token-exchange redirect_uri.

        Reproduces StreamlitGenerateEmbedUrl.java: strips the code and any
        pre-existing ``__embeddedApp`` / ``__parentOrigin`` params off the base,
        re-adds ``__parentOrigin`` (url-encoded) and ``__embeddedApp=true`` as
        query params, and appends the code as a ``#code=`` fragment.
        """
        code = self._extract_code(redirect_uri)
        parts = urlsplit(redirect_uri)

        # Drop the code carrier and our managed params from the base query, keep the rest.
        preserved = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key not in ("code", _PARAM_PARENT_ORIGIN, _PARAM_EMBEDDED_APP)
        ]

        # Build the new query: preserved params first, then our two managed params,
        # in the exact order the system function emits them.
        query_pieces = []
        if preserved:
            query_pieces.append(urlencode(preserved))
        query_pieces.append(
            _PARAM_PARENT_ORIGIN + "=" + quote(self._parent_origin, safe="")
        )
        query_pieces.append(_PARAM_EMBEDDED_APP + "=true")
        new_query = "&".join(query_pieces)

        new_fragment = "code=" + code

        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, new_query, new_fragment)
        )

    def get_embed_url(self) -> str:
        """Return the generated embed URL.

        Raises:
            ProgrammingError: if :meth:`prepare` has not been called yet.
        """
        if self._embed_url is None:
            raise ProgrammingError(
                msg="get_embed_url() called before prepare(); call prepare(...) first."
            )
        return self._embed_url

    @property
    def expires_in(self) -> int | None:
        """Seconds until the embed authorization code expires, if the server returned it."""
        return self._expires_in
