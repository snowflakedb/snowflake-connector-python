from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Collection

from .constants import OCSPMode

# ocsp_fail_open True/False opts into OCSP. None is the stored default and
# is not an opt-in. disable_ocsp_checks / insecure_mode only turn OCSP off
# when True; their stored False default is not an opt-in. Cache/timeout
# knobs never enable OCSP.
OCSP_MODE_PARAMS = frozenset({"disable_ocsp_checks", "ocsp_fail_open", "insecure_mode"})
OCSP_SUPPORT_PARAMS = frozenset(
    {"ocsp_response_cache_filename", "ocsp_root_certs_dict_lock_timeout"}
)
OCSP_EXPLICIT_PARAMS = OCSP_MODE_PARAMS | OCSP_SUPPORT_PARAMS

IGNORED_OCSP_SUPPORT_PARAMS_WARNING = (
    "OCSP is disabled unless you opt in. The following OCSP setting(s) will be "
    "ignored because none of ocsp_fail_open, disable_ocsp_checks, or "
    "insecure_mode was set: {params}. Set ocsp_fail_open=True or "
    "ocsp_fail_open=False to enable OCSP."
)


def snapshot_ocsp_explicit_params(params: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(name for name in OCSP_EXPLICIT_PARAMS if name in params)


def resolve_ocsp_mode(
    *,
    explicit: Collection[str],
    disable_ocsp_checks: bool,
    ocsp_fail_open: bool | None,
    insecure_mode: bool | None = None,
) -> OCSPMode:
    """Resolve OCSP mode from explicit user/toml presence plus stored values.

    ``ocsp_fail_open`` is the only opt-in: True = fail-open, False =
    fail-closed. None is the stored default and does not enable OCSP, even
    when the key is present (a caller forwarding DEFAULT_CONFIGURATION).

    Connection-property disable (``disable_ocsp_checks=True`` or
    ``insecure_mode=True``) always turns OCSP off, including when
    ``ocsp_fail_open`` is True/False. Presence of
    ``disable_ocsp_checks=False`` or ``insecure_mode=False`` is not an
    opt-in; those are the stored defaults.
    """
    if "disable_ocsp_checks" in explicit:
        disable_value = disable_ocsp_checks
    elif "insecure_mode" in explicit:
        disable_value = (
            insecure_mode if insecure_mode is not None else disable_ocsp_checks
        )
    else:
        disable_value = False

    if disable_value:
        return OCSPMode.DISABLE_OCSP_CHECKS
    if ocsp_fail_open is not None:
        return OCSPMode.FAIL_OPEN if ocsp_fail_open else OCSPMode.FAIL_CLOSED
    return OCSPMode.DISABLE_OCSP_CHECKS


def ignored_ocsp_support_params(explicit: Collection[str]) -> tuple[str, ...]:
    if any(name in explicit for name in OCSP_MODE_PARAMS):
        return ()
    return tuple(sorted(name for name in OCSP_SUPPORT_PARAMS if name in explicit))
