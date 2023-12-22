#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import test_utils

import snowflake.connector as connector
import snowflake.connector.connection as connection
import snowflake.connector.network as network
import snowflake.connector.ocsp_snowflake as ocsp_snowflake


def my_backoff_policy():
    yield 0
    raise Exception("OH NO!")


validate_sync_log_file = open(
    "/tmp/aiohttp_test/SFOCSP.validate.txt", mode="w", buffering=1
)
fetch_sync_log_file = open(
    "/tmp/aiohttp_test/SnowflakeRestful.fetch.txt", mode="w", buffering=1
)
connect_sync_log_file = open(
    "/tmp/aiohttp_test/connect sync.txt", mode="w", buffering=1
)
overall_sync_log_file = open(
    "/tmp/aiohttp_test/overall sync.txt", mode="w", buffering=1
)


@test_utils.wrap_function(overall_sync_log_file)
def do_thing():
    with connector.connect(
        **{
            "account": "sfctest0",
            "protocol": "https",
            "backoff_policy": my_backoff_policy,
            "ocsp_fail_open": False,
            "use_async": False,
        }
    ) as conn:
        pass


test_utils.wrap_method_with_timer(
    ocsp_snowflake.SnowflakeOCSP, "validate", validate_sync_log_file
)
test_utils.wrap_method_with_timer(
    network.SnowflakeRestful, "fetch", fetch_sync_log_file
)
test_utils.wrap_method_with_timer(
    connection.SnowflakeConnection, "__init__", connect_sync_log_file
)
for i in range(500):
    print(i)
    do_thing()
    time.sleep(0.1)

validate_sync_log_file.close()
fetch_sync_log_file.close()
connect_sync_log_file.close()
overall_sync_log_file.close()
