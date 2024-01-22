#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module


import snowflake.connector

try:
    from snowflake.connector.connection_diagnostic import (
        ConnectionDiagnostic,
        _decode_dict,
    )
except ImportError:
    pass


def test_https_host_report(caplog):
    connection_diag = ConnectionDiagnostic(
        account="test", host="test.snowflakecomputing.com"
    )
    https_host_report = connection_diag._ConnectionDiagnostic__https_host_report
    https_host_report(
        host="client-telemetry.snowflakecomputing.com",
        port=443,
        host_type="OUT_OF_BAND_TELEMETRY",
    )

    assert "OUT_OF_BAND_TELEMETRY: client-telemetry.snowflakecomputing.com" in ".".join(
        connection_diag.test_results["OUT_OF_BAND_TELEMETRY"]
    )


def test_decode_dict():
    test_dict = {b"CN": b"client-telemetry.snowflakecomputing.com"}
    result = _decode_dict(test_dict)

    assert result == {
        "CN": "client-telemetry.snowflakecomputing.com"
    }, "_decode_dict method failed, binary dict not converted."


def test_exception_raise_during_diag_fail(monkeypatch, caplog):
    def mock_run_post_test(self):
        raise ValueError("Diagnostic Test Failure")

    monkeypatch.setattr(
        snowflake.connector.connection_diagnostic.ConnectionDiagnostic,
        "run_post_test",
        mock_run_post_test,
    )

    try:
        snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpassword",
            database="TESTDB",
            warehouse="TESTWH",
            enable_connection_diag=True,
        )
    except Exception:
        pass

    assert "Diagnostic Test Failure" in caplog.text
