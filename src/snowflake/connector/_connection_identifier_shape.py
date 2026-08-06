#!/usr/bin/env python
"""Capture user-supplied connection-identifier provenance for in-band telemetry.

The shape captured here is consumed by ``SnowflakeConnection._log_connection_identifier_shape``
and emitted as a single ``client_connection_identifier_shape`` telemetry event
per successful login. The capture function inspects the raw kwargs passed to
``SnowflakeConnection.__config`` before any normalization (host inference,
account stripping of ``.global``, region extraction from dotted account) runs,
so the shape reflects user intent rather than the final post-normalization
state of the connection.

Removal of this module and the emission it backs is tracked in SNOW-3548350
(target: 2026-11-30).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .telemetry import TelemetryField


@dataclass(frozen=True)
class ConnectionIdentifierShape:
    """Provenance of connection-identifier fields the user supplied.

    All fields describe what the user supplied at the moment of input — they
    reflect intent, not the final post-normalization state of the connection.

    - ``account_provided``: the user explicitly set the ``account`` parameter
      (via ``connect(account=...)``, kwargs, or ``connections.toml`` merged
      into kwargs before ``__config`` runs).
    - ``account_with_region``: the raw account string the user typed contained
      a dot (e.g. ``"myacct.us-east-1"``), signaling the deprecated
      ``account.region`` embedded form. Set only on the raw input.
    - ``account_org_provided``: the raw account string carried a dash in its
      account portion (e.g. ``"myorg-myacct"``), signaling the org-prefixed
      form. Region-portion dashes (e.g. the ``-east-`` in
      ``"myacct.us-east-1"``) are intentionally not counted; only the portion
      before the first ``.`` is examined.
    - ``region_provided``: the user explicitly set the ``region`` parameter as
      a distinct kwarg. A region embedded inside a dotted account string is
      NOT ``region_provided``; that's ``account_with_region``.
    - ``host_provided``: the user explicitly set the ``host`` parameter.
    """

    account_provided: bool = False
    account_with_region: bool = False
    account_org_provided: bool = False
    region_provided: bool = False
    host_provided: bool = False


def _is_user_supplied_string(value: Any) -> bool:
    """A kwarg counts as user-supplied iff it's a non-empty string. Non-string
    truthy values (e.g. an accidentally-passed ``True`` / ``int``) are not
    treated as provided here — the regular ``__config`` validation will warn
    or error on them later, and shape capture is best kept conservative."""
    return isinstance(value, str) and value != ""


def record_input_shape(kwargs: Mapping[str, Any]) -> ConnectionIdentifierShape:
    """Capture the connection-identifier shape from the raw kwargs that
    ``SnowflakeConnection.__config`` receives.

    Must be invoked before any normalization (the ``setattr`` loop in
    ``__config``, the ``construct_hostname`` call for host inference, or any
    ``parse_account`` stripping) — otherwise inferred values are
    indistinguishable from user-supplied ones and ``host_provided`` /
    ``account_provided`` are no longer trustworthy.
    """
    account = kwargs.get("account")
    region = kwargs.get("region")
    host = kwargs.get("host")

    account_provided = _is_user_supplied_string(account)
    account_with_region = False
    account_org_provided = False
    if account_provided:
        # Only a dot at position > 0 splits the string into account / region;
        # a leading dot (pathological input like ``.us-east-1``) leaves the
        # whole string as the account portion. Mirrors gosnowflake's
        # ``recordAccountShape`` (internal/config/dsn.go), which gates on
        # ``i > 0`` so the dash search runs against the full raw value when
        # there is no real account/region split.
        dot_index = account.find(".")
        if dot_index > 0:
            account_with_region = True
            account_portion = account[:dot_index]
        else:
            account_portion = account
        # ``Contains(accountPortion, "-")`` in Go — any dash anywhere in the
        # account portion (including position 0) flips the flag. The
        # region-tail dashes are excluded by virtue of being outside
        # ``account_portion``, not by a position check.
        account_org_provided = "-" in account_portion

    return ConnectionIdentifierShape(
        account_provided=account_provided,
        account_with_region=account_with_region,
        account_org_provided=account_org_provided,
        region_provided=_is_user_supplied_string(region),
        host_provided=_is_user_supplied_string(host),
    )


def build_shape_telemetry_message(shape: ConnectionIdentifierShape) -> dict[str, str]:
    """Build the wire-format payload for the ``client_connection_identifier_shape``
    in-band telemetry event from a captured ``ConnectionIdentifierShape``.

    Hoisted out of the sync / async ``_log_connection_identifier_shape``
    emitters so both branches stay in lockstep — the five payload keys
    (``account_provided``, ``account_with_region``, ``account_org_provided``,
    ``region_provided``, ``host_provided``) and their stringified-lowercase
    boolean values are byte-identical across sibling drivers and must remain
    so. Changing this builder is the only place that affects the wire format.

    Booleans are stringified as lowercase ``"true"`` / ``"false"`` (matching
    JSON-style boolean text) for cross-driver parity with gosnowflake's
    ``strconv.FormatBool`` and the JDBC / Node.js siblings.

    TODO(SNOW-3548350): remove with the telemetry emission
    (target: 2026-11-30).
    """
    return {
        TelemetryField.KEY_TYPE.value: TelemetryField.CONNECTION_IDENTIFIER_SHAPE.value,
        TelemetryField.KEY_ACCOUNT_PROVIDED.value: str(shape.account_provided).lower(),
        TelemetryField.KEY_ACCOUNT_WITH_REGION.value: str(
            shape.account_with_region
        ).lower(),
        TelemetryField.KEY_ACCOUNT_ORG_PROVIDED.value: str(
            shape.account_org_provided
        ).lower(),
        TelemetryField.KEY_REGION_PROVIDED.value: str(shape.region_provided).lower(),
        TelemetryField.KEY_HOST_PROVIDED.value: str(shape.host_provided).lower(),
    }
