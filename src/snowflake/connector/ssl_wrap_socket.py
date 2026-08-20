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
from typing import TYPE_CHECKING, Any

import certifi
import OpenSSL.SSL

from .constants import OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT, OCSPMode
from .crl import CertRevocationCheckMode, CRLConfig, CRLValidator
from .errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from .errors import OperationalError
from .session_manager import SessionManager, SessionManagerFactory
from .vendored.urllib3 import connection as connection_
from .vendored.urllib3.contrib.pyopenssl import PyOpenSSLContext, WrappedSocket
from .vendored.urllib3.util import ssl_ as ssl_
from .vendored.urllib3.util.ssl_match_hostname import CertificateError, match_hostname

if TYPE_CHECKING:
    from cryptography import x509

DEFAULT_OCSP_MODE: OCSPMode = OCSPMode.FAIL_OPEN
FEATURE_OCSP_MODE: OCSPMode = DEFAULT_OCSP_MODE
FEATURE_ROOT_CERTS_DICT_LOCK_TIMEOUT: int = (
    OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT
)
DEFAULT_CRL_CONFIG: CRLConfig = CRLConfig()
FEATURE_CRL_CONFIG: CRLConfig = DEFAULT_CRL_CONFIG

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


def _nonnegative_options(value: int) -> int:
    """Return *value* as the non-negative bitmask pyOpenSSL/cryptography expects.

    ``ssl.SSLContext.options`` is exposed through a signed, platform-width C
    ``long``. On Windows that type is 32 bits, so the common default mask (which
    has bit 31 set, e.g. ``0x82520050``) is returned as a *negative* Python int.
    cryptography's binding marshals the value into an unsigned parameter and
    rejects negatives with ``OverflowError: can't convert negative number to
    unsigned`` -- which previously aborted every Windows TLS handshake the
    moment we carried these options onto the substituted ``PyOpenSSLContext``.
    Recover the intended unsigned 32-bit mask; values that are already
    non-negative (every other platform) pass through unchanged.
    """
    return value & 0xFFFFFFFF if value < 0 else value


def _apply_stdlib_hardening(dst: PyOpenSSLContext, src: ssl.SSLContext | None) -> None:
    """Carry TLS hardening from a stdlib ``SSLContext`` onto ``dst``.

    The connector replaces the stdlib ``ssl.SSLContext`` that urllib3 builds
    (or that a caller supplied) with a ``PyOpenSSLContext``. Without copying the
    original context's hardening forward, the substitution silently drops the
    TLS-version floor and ``OP_NO_*`` options urllib3 configured and
    any hardening a caller set on a supplied context. Copy the
    settings we can read back; fall back to urllib3's default floor when there
    is no source context to mirror.

    Limitation: cipher restrictions and pinned CA material (``cadata`` /
    ``load_verify_locations``) cannot be read back out of an ``ssl.SSLContext``,
    so they cannot be transferred here. Honoring caller-supplied pinning needs a
    dedicated, supported channel and is tracked as a follow-up.
    """
    if isinstance(src, ssl.SSLContext):
        # Mirror the protocol-version floor/ceiling and OpenSSL options the
        # original context carried (e.g. TLS 1.2 minimum, OP_NO_SSLv3,
        # OP_NO_COMPRESSION) plus any caller hardening (e.g. VERIFY_X509_STRICT).
        for attr in ("minimum_version", "maximum_version", "verify_flags"):
            try:
                setattr(dst, attr, getattr(src, attr))
            except (ValueError, OSError, OpenSSL.SSL.Error):
                # Best-effort; an unsupported value must not break the handshake.
                pass
        try:
            dst.options |= _nonnegative_options(src.options)
        except (ValueError, OSError, OpenSSL.SSL.Error, OverflowError, TypeError):
            # Best-effort; carrying options forward must never break the
            # handshake even if a value can't be marshalled into pyOpenSSL.
            pass
    else:
        # No source context to mirror (no ssl_context was supplied): restore the
        # hardening urllib3's create_urllib3_context() would have applied.
        try:
            dst.minimum_version = ssl.TLSVersion.TLSv1_2
            dst.options |= ssl.OP_NO_COMPRESSION
        except (ValueError, OSError, OpenSSL.SSL.Error, OverflowError, TypeError):
            pass


def _build_context_with_partial_chain(
    cafile: str | None, src_context: ssl.SSLContext | None = None
) -> PyOpenSSLContext:
    """Create PyOpenSSL context configured for CERT_REQUIRED and partial-chain trust.

    When ``src_context`` is the stdlib context being replaced, its TLS hardening
    (version floor, options, verify flags) is carried forward so the
    substitution does not weaken the connection.
    """
    ctx = PyOpenSSLContext(ssl_.PROTOCOL_TLS_CLIENT)
    try:
        ctx.verify_mode = ssl.CERT_REQUIRED
    except Exception:
        pass
    _apply_stdlib_hardening(ctx, src_context)
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
        return (
            SessionManagerFactory.get_manager() if create_default_if_missing else None
        )
    context_session_manager = sm_weak_ref()

    if context_session_manager is None:
        return (
            SessionManagerFactory.get_manager() if create_default_if_missing else None
        )

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
    connection_.ssl_wrap_socket = ssl_wrap_socket_with_cert_revocation_checks


def _load_trusted_certificates(cafile: str | None) -> list[x509.Certificate]:
    # Use default SSL context to load the CA file and get the certificates
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=cafile)
    certs = ctx.get_ca_certs(binary_form=True)
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_der_x509_certificate

    return [load_der_x509_certificate(cert, default_backend()) for cert in certs]


def _verify_hostname_after_handshake(
    wrapped_socket: WrappedSocket,
    server_hostname: str | None,
    ssl_context: Any,
) -> None:
    """Match the peer certificate against *server_hostname*."""
    # Honor explicitly-disabled certificate verification (CERT_NONE) first; when
    # verification is off there is nothing to assert about server identity, so a
    # missing hostname is acceptable. Check this before the hostname so we only
    # skip when the caller genuinely opted out of verification.
    verify_mode = getattr(ssl_context, "verify_mode", ssl.CERT_REQUIRED)
    if verify_mode == ssl.CERT_NONE:
        return

    # Verification is required but there is no host to match against (e.g. TLS
    # without SNI). Fail closed rather than accepting the peer: without a
    # hostname we cannot assert server identity.
    if not server_hostname:
        raise CertificateError(
            "no server hostname supplied to match against the peer certificate; "
            "cannot verify server identity"
        )

    # Normalize bracketed / scoped IPv6 literals the same way urllib3 does:
    # strip the brackets and drop any "%scope" suffix before testing for an IP,
    # since Python's ssl module treats scoped addresses as DNS hostnames.
    normalized = server_hostname.strip("[]")
    if "%" in normalized:
        normalized = normalized[: normalized.rfind("%")]
    if ssl_.is_ipaddress(normalized):
        server_hostname = normalized

    cert = wrapped_socket.getpeercert()
    try:
        match_hostname(cert, server_hostname)
    except CertificateError as e:
        log.warning(
            "Certificate did not match expected hostname: %s. Certificate: %s",
            server_hostname,
            cert,
        )
        # Attach the cert so callers catching CertificateError can inspect it,
        # matching urllib3's own _match_hostname behavior.
        e._peer_cert = cert
        wrapped_socket.close()
        raise


@wraps(ssl_.ssl_wrap_socket)
def ssl_wrap_socket_with_cert_revocation_checks(
    *args: Any, **kwargs: Any
) -> WrappedSocket:
    # Bind passed args/kwargs to the underlying signature to support both positional and keyword calls
    bound = _sig(ssl_.ssl_wrap_socket).bind_partial(*args, **kwargs)
    params = bound.arguments

    server_hostname = params.get("server_hostname")

    # Ensure CA bundle default if not provided
    if not params.get("ca_certs"):
        params["ca_certs"] = certifi.where()

    # Ensure PyOpenSSL context with partial-chain is used if none or wrong type provided
    provided_ctx = params.get("ssl_context")
    cafile_for_ctx = _resolve_cafile(params)
    if not isinstance(provided_ctx, PyOpenSSLContext):
        # Carry the replaced stdlib context's TLS hardening forward so the
        # substitution doesn't silently weaken the connection.
        params["ssl_context"] = _build_context_with_partial_chain(
            cafile_for_ctx, src_context=provided_ctx
        )
    else:
        # If a PyOpenSSLContext is provided, ensure it trusts the provided CA and partial-chain is enabled
        _ensure_partial_chain_on_context(provided_ctx, cafile_for_ctx)

    ret = ssl_.ssl_wrap_socket(**params)

    _verify_hostname_after_handshake(ret, server_hostname, params.get("ssl_context"))

    log.debug(
        "CRL Check Mode: %s",
        FEATURE_CRL_CONFIG.cert_revocation_check_mode.name,
    )
    if (
        FEATURE_CRL_CONFIG.cert_revocation_check_mode
        != CertRevocationCheckMode.DISABLED
    ):
        crl_validator = CRLValidator.from_config(
            FEATURE_CRL_CONFIG,
            get_current_session_manager(),
            trusted_certificates=_load_trusted_certificates(cafile_for_ctx),
        )
        if not crl_validator.validate_connection(ret.connection):
            raise OperationalError(
                msg=(
                    "The certificate is revoked or "
                    "could not be validated via CRL: hostname={}".format(
                        server_hostname
                    )
                ),
                errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
            )
        log.debug(
            "The certificate revocation check was successful. No additional checks will be performed."
        )
        return ret

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
            root_certs_dict_lock_timeout=FEATURE_ROOT_CERTS_DICT_LOCK_TIMEOUT,
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
