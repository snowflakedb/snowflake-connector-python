#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import test_utils

import snowflake.connector as connector
import snowflake.connector.ocsp_snowflake as ocsp_snowflake


def my_backoff_policy():
    yield 0
    raise Exception("WTF WHY DID SOMETHING FAIL?")


validate_sync_log_file = open(
    "/tmp/aiohttp_test/SFOCSP.validate.txt", mode="w", buffering=1
)
sequential_sync_log_file = open(
    "/tmp/aiohttp_test/SFOCSP._validate_certificates_sequential.txt",
    mode="w",
    buffering=1,
)
fetch_ocsp_sync_log_file = open(
    "/tmp/aiohttp_test/SFOCSP._fetch_ocsp_response.txt", mode="w", buffering=1
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
            "use_async": False,
        }
    ) as conn:
        pass


test_utils.wrap_method_with_timer(
    ocsp_snowflake.SnowflakeOCSP, "validate", validate_sync_log_file
)
test_utils.wrap_method_with_timer(
    ocsp_snowflake.SnowflakeOCSP,
    "_validate_certificates_sequential",
    sequential_sync_log_file,
)
test_utils.wrap_method_with_timer(
    ocsp_snowflake.SnowflakeOCSP, "_fetch_ocsp_response", fetch_ocsp_sync_log_file
)
for i in range(100):
    print(i)
    do_thing()
    time.sleep(1)

validate_sync_log_file.close()
sequential_sync_log_file.close()
fetch_ocsp_sync_log_file.close()
