#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

try:
    from packaging import version  # Use packaging to compare versions

    from snowflake.connector.vendored import urllib3

    vendored_imported = True
except ModuleNotFoundError:
    vendored_imported = False

# Determine the version of urllib3 if it's imported
if vendored_imported:
    urllib3_version = version.parse(urllib3.__version__)
else:
    urllib3_version = version.parse("0")

# Define the version where the socket bug is fixed
fixed_version = version.parse("2.0.0")


@pytest.mark.skipif(
    not vendored_imported, reason="vendored library is not imported for old driver"
)
@pytest.mark.skipif(
    urllib3_version >= fixed_version,
    reason="Test is not necessary for urllib3 versions 2.0.0 and above where the bug is fixed",
)
def test_local_fix_for_closed_socket_bug():
    # Test for closed socket bug as described in:
    # https://github.com/urllib3/urllib3/issues/1878#issuecomment-641534573
    http = urllib3.PoolManager(maxsize=1)

    def _execute_request():
        resp = http.request(
            method="GET", url="http://httpbin.org", preload_content=False
        )
        try:
            # Simulate the closed socket condition
            resp._connection.sock.close()  # Direct manipulation of internal attributes
        finally:
            resp.release_conn()
            resp.close()

    # Perform the request twice to trigger the error condition
    _execute_request()
    try:
        _execute_request()
    except ValueError as e:
        if "file descriptor cannot be a negative" in str(e):
            raise AssertionError(
                "Second _execute_request failed due to the closed socket issue. "
                "This is a known bug in older versions of urllib3."
            )
        else:
            raise
