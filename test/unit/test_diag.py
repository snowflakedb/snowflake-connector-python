#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import snowflake.connector


def test_exception_raise_during_diag_fail(monkeypatch, caplog):
    def mock_run_post_test(self):
        raise ValueError("Diagnostic Test Failure")

    monkeypatch.setattr(
        snowflake.connector.connection_diagnostic.ConnectionDiagnostic,
        "run_post_test",
        mock_run_post_test,
    )

    snowflake.connector.connect(
        account="testaccount",
        user="testuser",
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
        enable_connection_diag=True,
    )

    assert "Diagnostic Test Failure" in caplog.text
