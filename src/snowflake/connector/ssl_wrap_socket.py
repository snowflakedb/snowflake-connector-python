from __future__ import annotations

#
# SSL wrap socket for PyOpenSSL.
# Mostly copied from
#
# https://github.com/shazow/urllib3/blob/master/urllib3/contrib/pyopenssl.py
#
# and added OCSP validator on the top.
import logging
import os
import ssl
import time
import weakref
from contextvars import ContextVar
from functools import wraps
from inspect import signature as _sig
from socket import socket
from typing import Any

import certifi
import OpenSSL.SSL

from .constants import OCSPMode
from .errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from .errors import OperationalError
from .session_manager import SessionManager
from .vendored.urllib3 import connection as connection_
from .vendored.urllib3.contrib.pyopenssl import PyOpenSSLContext, WrappedSocket
from .vendored.urllib3.util import ssl_ as ssl_

DEFAULT_OCSP_MODE: OCSPMode = OCSPMode.FAIL_OPEN
FEATURE_OCSP_MODE: OCSPMode = DEFAULT_OCSP_MODE

"""
OCSP Response cache file name
"""
FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME: str | None = None

log = logging.getLogger(__name__)


# Helper utilities (private)
def _resolve_cafile(kwargs: dict[str, Any]) -> str | None:
    """Resolve CA bundle path from kwargs or standard environment variables.

    Precedence:
      1) kwargs['ca_certs'] if provided by caller
      2) REQUESTS_CA_BUNDLE
      3) SSL_CERT_FILE
    """
    caf = kwargs.get("ca_certs")
    if caf:
        return caf
    return os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")


def _ensure_partial_chain_on_context(ctx: PyOpenSSLContext, cafile: str | None) -> None:
    """Load CA bundle (when provided) and enable OpenSSL partial-chain support on ctx."""
    if cafile:
        try:
            ctx.load_verify_locations(cafile=cafile, capath=None)
        except (ssl.SSLError, OSError, ValueError):
            # Leave context unchanged; handshake/validation surfaces failures
            pass
    try:
        store = ctx._ctx.get_cert_store()
        from OpenSSL import crypto as _crypto

        if hasattr(_crypto, "X509StoreFlags") and hasattr(
            _crypto.X509StoreFlags, "PARTIAL_CHAIN"
        ):
            store.set_flags(_crypto.X509StoreFlags.PARTIAL_CHAIN)
    except (AttributeError, ImportError, OpenSSL.SSL.Error, OSError, ValueError):
        # Best-effort; if not available, default chain building applies
        pass


def _build_context_with_partial_chain(cafile: str | None) -> PyOpenSSLContext:
    """Create PyOpenSSL context configured for CERT_REQUIRED and partial-chain trust."""
    ctx = PyOpenSSLContext(ssl_.PROTOCOL_TLS_CLIENT)
    try:
        ctx.verify_mode = ssl.CERT_REQUIRED
    except Exception:
        pass
    _ensure_partial_chain_on_context(ctx, cafile)
    return ctx


# Store a *weak* reference so that the context variable doesn’t prolong the
# lifetime of the SessionManager. Once all owning connections are GC-ed the
# weakref goes dead and OCSP will fall back to its local manager (but most
# likely won't be used ever again anyway).
_CURRENT_SESSION_MANAGER: ContextVar[weakref.ref[SessionManager] | None] = ContextVar(
    "_CURRENT_SESSION_MANAGER",
    default=None,
)


def get_current_session_manager(
    create_default_if_missing: bool = True, **clone_kwargs
) -> SessionManager | None:
    """Return the SessionManager associated with the current handshake, if any.

    If the weak reference is dead or no manager was set, returns ``None``.
    """
    sm_weak_ref = _CURRENT_SESSION_MANAGER.get()
    if sm_weak_ref is None:
        return SessionManager() if create_default_if_missing else None
    context_session_manager = sm_weak_ref()

    if context_session_manager is None:
        return SessionManager() if create_default_if_missing else None

    return context_session_manager.clone(**clone_kwargs)


def set_current_session_manager(sm: SessionManager | None) -> Any:
    """Set the SessionManager for the current execution context.

    Called from SnowflakeConnection so that OCSP downloads
    use the same proxy / header configuration as the initiating connection.

    Alternative approach would be moving method inject_into_urllib3() inside
    connection initialization, but in case this delay (from module import time
    to connection initialization time) would cause some code to break we stayed
    with this approach, having in mind soon OCSP deprecation.
    """
    return _CURRENT_SESSION_MANAGER.set(weakref.ref(sm) if sm is not None else None)


def reset_current_session_manager(token) -> None:
    """Restore previous SessionManager context stored in *token* (from ContextVar.set)."""
    try:
        _CURRENT_SESSION_MANAGER.reset(token)
    except Exception:
        # ignore invalid token errors
        pass


def inject_into_urllib3() -> None:
    """Monkey-patch urllib3 with PyOpenSSL-backed SSL-support and OCSP."""
    log.debug("Injecting ssl_wrap_socket_with_ocsp")
    connection_.ssl_wrap_socket = ssl_wrap_socket_with_ocsp


@wraps(ssl_.ssl_wrap_socket)
def ssl_wrap_socket_with_ocsp(*args: Any, **kwargs: Any) -> WrappedSocket:
    # Bind passed args/kwargs to the underlying signature to support both positional and keyword calls
    bound = _sig(ssl_.ssl_wrap_socket).bind_partial(*args, **kwargs)
    params = bound.arguments

    server_hostname = params.get("server_hostname")

    # Ensure CA bundle default if not provided
    if not params.get("ca_certs"):
        params["ca_certs"] = certifi.where()

    # Ensure PyOpenSSL context with partial-chain is used if none or wrong type provided
    provided_ctx = params.get("ssl_context")
    if not isinstance(provided_ctx, PyOpenSSLContext):
        cafile_for_ctx = _resolve_cafile(params)
        params["ssl_context"] = _build_context_with_partial_chain(cafile_for_ctx)
    else:
        # If a PyOpenSSLContext is provided, ensure it trusts the provided CA and partial-chain is enabled
        _ensure_partial_chain_on_context(provided_ctx, _resolve_cafile(params))

    ret = ssl_.ssl_wrap_socket(**params)

    log.debug(
        "OCSP Mode: %s, OCSP response cache file name: %s",
        FEATURE_OCSP_MODE.name,
        FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
    )
    if FEATURE_OCSP_MODE != OCSPMode.DISABLE_OCSP_CHECKS:
        from .ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP

        v = SFOCSP(
            ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
            use_fail_open=FEATURE_OCSP_MODE == OCSPMode.FAIL_OPEN,
            hostname=server_hostname,
        ).validate(server_hostname, ret.connection)
        if not v:
            raise OperationalError(
                msg=f"The certificate is revoked or could not be validated: hostname={server_hostname}",
                errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
            )
    else:
        log.debug(
            "This connection does not perform OCSP checks. "
            "Revocation status of the certificate will not be checked against OCSP Responder."
        )

    return ret


def _openssl_connect(
    hostname: str, port: int = 443, max_retry: int = 20, timeout: int | None = None
) -> OpenSSL.SSL.Connection:
    """The OpenSSL connection without validating certificates.

    This is used to diagnose SSL issues.
    """
    err = None
    sleeping_time = 1
    for _ in range(max_retry):
        try:
            client = socket()
            client.connect((hostname, port))
            context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            if timeout is not None:
                context.set_timeout(timeout)
            client_ssl = OpenSSL.SSL.Connection(context, client)
            client_ssl.set_connect_state()
            client_ssl.set_tlsext_host_name(hostname.encode("utf-8"))
            client_ssl.do_handshake()
            return client_ssl
        except (
            OpenSSL.SSL.SysCallError,
            OSError,
        ) as ex:
            err = ex
            sleeping_time = min(sleeping_time * 2, 16)
            time.sleep(sleeping_time)
    if err:
        raise err
