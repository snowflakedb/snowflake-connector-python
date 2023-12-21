#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import test_utils

import snowflake.connector as connector
import snowflake.connector.event_loop_runner as event_loop_runner
import snowflake.connector.network_async as network_async
import snowflake.connector.ocsp_snowflake_async as ocsp_snowflake_async


def my_backoff_policy():
    yield 0
    raise Exception("WTF WHY DID SOMETHING FAIL?")


event_loop_runner.start()

validate_async_log_file = open(
    "/tmp/aiohttp_test/SFOCSP.validate_async.txt", mode="w", buffering=1
)
sequential_async_log_file = open(
    "/tmp/aiohttp_test/SFOCSP._validate_certificates_concurrent_async.txt",
    mode="w",
    buffering=1,
)
fetch_ocsp_async_log_file = open(
    "/tmp/aiohttp_test/SFOCSP._fetch_ocsp_response_async.txt", mode="w", buffering=1
)


def do_thing():
    with connector.connect(
        **{
            "account": "sfctest0",
            "user": "yqiu_test",
            "role": "testrole_yqiu",
            "password": "T3sttest",
            "database": "testdb_yqiu",
            "protocol": "https",
            "backoff_policy": my_backoff_policy,
            # "proxy_host": "127.0.0.1",
            # "proxy_port": "5000",
            "ocsp_fail_open": False,
            "use_async": True,
        }
    ) as conn:
        pass


test_utils.wrap_method_with_timer_async(
    ocsp_snowflake_async.SnowflakeOCSPAsync, "validate_async", validate_async_log_file
)
test_utils.wrap_method_with_timer_async(
    ocsp_snowflake_async.SnowflakeOCSPAsync,
    "_validate_certificates_concurrent_async",
    sequential_async_log_file,
)
test_utils.wrap_method_with_timer_async(
    ocsp_snowflake_async.SnowflakeOCSPAsync,
    "_fetch_ocsp_response_async",
    fetch_ocsp_async_log_file,
)
for i in range(100):
    print(i)
    do_thing()
    time.sleep(1)

validate_async_log_file.close()
sequential_async_log_file.close()
fetch_ocsp_async_log_file.close()

event_loop_runner.stop()
