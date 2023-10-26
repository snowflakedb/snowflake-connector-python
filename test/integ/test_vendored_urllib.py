#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

try:
    from snowflake.connector.vendored import urllib3

    vendored_imported = True
except ModuleNotFoundError:
    vendored_imported = False


@pytest.mark.skipif(
    not vendored_imported, reason="vendored library is not imported for old driver"
)
def test_local_fix_for_closed_socket_bug():
    # https://github.com/urllib3/urllib3/issues/1878#issuecomment-641534573
    http = urllib3.PoolManager(maxsize=1)

    def _execute_request():
        resp = http.request(
            method="GET", url="http://httpbin.org", preload_content=False
        )
        resp._connection.sock.close()
        resp.release_conn()
        resp.close()
        return resp

    _execute_request()
    try:
        _execute_request()
    except ValueError as e:
        if "file descriptor cannot be a negative" in str(e):
            raise AssertionError(
                "Second _execute_request failed. See linked github issue comment"
            )
        else:
            raise e
