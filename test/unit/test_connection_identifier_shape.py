#!/usr/bin/env python
"""Unit tests for ``snowflake.connector._connection_identifier_shape``.

These exercise the pure ``record_input_shape`` helper against a truth table of
``account``/``region``/``host`` kwargs combinations. Telemetry emission is
covered separately in ``test_connection_identifier_shape_telemetry.py``.
"""
from __future__ import annotations

import pytest

from snowflake.connector._connection_identifier_shape import (
    ConnectionIdentifierShape,
    build_shape_telemetry_message,
    record_input_shape,
)
from snowflake.connector.telemetry import TelemetryField


@pytest.mark.parametrize(
    "name,kwargs,expected",
    [
        (
            "empty",
            {},
            ConnectionIdentifierShape(),
        ),
        (
            "bare_account_locator",
            {"account": "myacct"},
            ConnectionIdentifierShape(account_provided=True),
        ),
        (
            "account_with_region_via_dot",
            # Dot in the raw account string signals the deprecated
            # "account.region" embedded form.
            {"account": "myacct.us-east-1"},
            ConnectionIdentifierShape(
                account_provided=True,
                account_with_region=True,
            ),
        ),
        (
            "org_prefixed_account",
            # Dash in the account portion (before any dot) signals the
            # org-prefixed form.
            {"account": "myorg-myacct"},
            ConnectionIdentifierShape(
                account_provided=True,
                account_org_provided=True,
            ),
        ),
        (
            "org_prefixed_account_with_region_via_dot",
            # Both forms in one string: dot AND dash in the account portion.
            {"account": "myorg-myacct.us-east-1"},
            ConnectionIdentifierShape(
                account_provided=True,
                account_with_region=True,
                account_org_provided=True,
            ),
        ),
        (
            "region_dashes_not_counted_as_org",
            # Region-portion dashes (the "-east-" inside "us-east-1") must
            # not be counted toward account_org_provided. Only the portion
            # before the first dot is inspected for the org dash.
            {"account": "myacct.us-east-1"},
            ConnectionIdentifierShape(
                account_provided=True,
                account_with_region=True,
                # account_org_provided stays False.
            ),
        ),
        (
            "account_and_region_kwargs",
            # User supplied region as a distinct kwarg, not embedded in
            # account — that's region_provided=True, account_with_region=False.
            {"account": "myacct", "region": "us-east-1"},
            ConnectionIdentifierShape(
                account_provided=True,
                region_provided=True,
            ),
        ),
        (
            "host_only",
            {"host": "myacct.snowflakecomputing.com"},
            ConnectionIdentifierShape(host_provided=True),
        ),
        (
            "all_three",
            {
                "account": "myacct",
                "region": "us-east-1",
                "host": "myacct.us-east-1.aws.snowflakecomputing.com",
            },
            ConnectionIdentifierShape(
                account_provided=True,
                region_provided=True,
                host_provided=True,
            ),
        ),
        (
            "empty_strings_are_not_provided",
            # Defensive: empty-string kwargs count as not provided.
            {"account": "", "region": "", "host": ""},
            ConnectionIdentifierShape(),
        ),
        (
            "none_values_are_not_provided",
            {"account": None, "region": None, "host": None},
            ConnectionIdentifierShape(),
        ),
        (
            "non_string_values_are_not_provided",
            # Defensive: non-string truthy values do not flip any flag.
            # The regular __config validation warns/errors on these later.
            {"account": True, "region": 1, "host": ["x"]},
            ConnectionIdentifierShape(),
        ),
        (
            "leading_dot_account_does_not_split",
            # Pathological input ``.us-east-1`` — Go's recordAccountShape
            # gates the dot-split on ``i > 0`` so a leading dot leaves the
            # full string as the "account portion". The dash search then
            # runs over the whole value and flips account_org_provided.
            # account_with_region stays False because there is no real
            # account/region split (the account portion is genuinely empty
            # otherwise).
            {"account": ".us-east-1"},
            ConnectionIdentifierShape(
                account_provided=True,
                account_with_region=False,
                account_org_provided=True,
            ),
        ),
        (
            "trailing_dot_account_with_empty_region",
            # Single trailing dot — splits into "myacct" + "" — region tail
            # is empty but the split semantics still hold. Mirrors Go,
            # which sets AccountWithRegion=true for any ``dotIndex > 0``
            # regardless of whether the region portion has content.
            {"account": "myacct."},
            ConnectionIdentifierShape(
                account_provided=True,
                account_with_region=True,
                account_org_provided=False,
            ),
        ),
    ],
)
def test_record_input_shape(
    name: str, kwargs: dict, expected: ConnectionIdentifierShape
) -> None:
    del name  # used by pytest for sub-test identification
    assert record_input_shape(kwargs) == expected


def test_build_shape_telemetry_message_renders_lowercase_booleans() -> None:
    """The wire-format payload must stringify booleans as lowercase
    ``"true"`` / ``"false"`` (matching gosnowflake's ``strconv.FormatBool``
    and the Node.js / JDBC siblings). Any drift here breaks cross-driver
    parity for the same logical event."""
    shape = ConnectionIdentifierShape(
        account_provided=True,
        account_with_region=False,
        account_org_provided=True,
        region_provided=False,
        host_provided=True,
    )
    msg = build_shape_telemetry_message(shape)
    assert msg == {
        TelemetryField.KEY_TYPE.value: TelemetryField.CONNECTION_IDENTIFIER_SHAPE.value,
        TelemetryField.KEY_ACCOUNT_PROVIDED.value: "true",
        TelemetryField.KEY_ACCOUNT_WITH_REGION.value: "false",
        TelemetryField.KEY_ACCOUNT_ORG_PROVIDED.value: "true",
        TelemetryField.KEY_REGION_PROVIDED.value: "false",
        TelemetryField.KEY_HOST_PROVIDED.value: "true",
    }


def test_build_shape_telemetry_message_default_shape_emits_all_false() -> None:
    """The default ``ConnectionIdentifierShape()`` (no fields supplied)
    renders every boolean field as ``"false"`` — exercising the path where
    the user provided no connection-identifier hints at all."""
    msg = build_shape_telemetry_message(ConnectionIdentifierShape())
    assert msg[TelemetryField.KEY_ACCOUNT_PROVIDED.value] == "false"
    assert msg[TelemetryField.KEY_ACCOUNT_WITH_REGION.value] == "false"
    assert msg[TelemetryField.KEY_ACCOUNT_ORG_PROVIDED.value] == "false"
    assert msg[TelemetryField.KEY_REGION_PROVIDED.value] == "false"
    assert msg[TelemetryField.KEY_HOST_PROVIDED.value] == "false"


def test_record_input_shape_ignores_unrelated_kwargs() -> None:
    """Only ``account``, ``region``, ``host`` are inspected; other kwargs
    cannot influence the captured shape."""
    shape = record_input_shape(
        {
            "user": "u",
            "password": "p",
            "warehouse": "wh",
            "database": "db",
            "schema": "s",
            "authenticator": "snowflake",
        }
    )
    assert shape == ConnectionIdentifierShape()
