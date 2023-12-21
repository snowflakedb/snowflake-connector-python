#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import os
import time

import test_utils

import snowflake.connector as connector
import snowflake.connector.cursor as cursor
import snowflake.connector.event_loop_runner as event_loop_runner
import snowflake.connector.file_transfer_agent_async as file_transfer_agent_async
import snowflake.connector.network_async as network_async
import snowflake.connector.result_batch_async as result_batch_async
import snowflake.connector.storage_client_async as storage_client_async


def my_backoff_policy():
    yield 0
    raise Exception("WTF WHY DID SOMETHING FAIL?")


fetch_async_log_file = open(
    "/tmp/aiohttp_test/SnowflakeRestfulAsync.fetch.txt", mode="w", buffering=1
)
download_async_log_file = open(
    "/tmp/aiohttp_test/ResultBatchAsync._download_async" ".txt", mode="w", buffering=1
)
storage_req_async_log_file = open(
    "/tmp/aiohttp_test/SnowflakeStorageClientAsync._send_request_with_retry_async.txt",
    mode="w",
    buffering=1,
)
ft_agent_async_log_file = open(
    "/tmp/aiohttp_test/SnowflakeFileTransferAgentAsync.execute.txt",
    mode="w",
    buffering=1,
)
execute_async_log_file = open(
    "/tmp/aiohttp_test/execute async.txt", mode="w", buffering=1
)
overall_async_log_file = open(
    "/tmp/aiohttp_test/overall async.txt", mode="w", buffering=1
)

event_loop_runner.start()
conn = connector.connect(
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
)


@test_utils.wrap_function(overall_async_log_file)
def do_thing(conn, i):
    cur = conn.cursor()
    cur.execute("USE SCHEMA playground")
    # cur.execute("SELECT * FROM player_stats")
    # cur.execute("CALL SYSTEM$WAIT(1);")
    # cur.execute(f"select seq4() as foo from table(generator(rowcount=>1000000))")
    # cur.execute(f"GET @%player_stats file:///tmp/async_{i}")
    cur.execute("REMOVE @%player_stats")
    cur.execute("PUT file:///tmp/EGABEGA.txt.gz @%player_stats")
    _ = [e for e in cur]


test_utils.wrap_method_with_timer(
    network_async.SnowflakeRestfulAsync, "fetch", fetch_async_log_file
)
test_utils.wrap_method_with_timer_async(
    result_batch_async.ResultBatchAsync, "_download_async", download_async_log_file
)
test_utils.wrap_method_with_timer_async(
    storage_client_async.SnowflakeStorageClientAsync,
    "_send_request_with_retry_async",
    storage_req_async_log_file,
)
test_utils.wrap_method_with_timer(
    file_transfer_agent_async.SnowflakeFileTransferAgentAsync,
    "execute",
    ft_agent_async_log_file,
)
test_utils.wrap_method_with_timer(
    cursor.SnowflakeCursor, "execute", execute_async_log_file
)
for i in range(25):
    # try:
    #     os.mkdir(f"/tmp/async_{i}")
    # except:
    #     pass
    print(i)
    do_thing(conn, i)
    time.sleep(0.1)

event_loop_runner.stop()

fetch_async_log_file.close()
download_async_log_file.close()
storage_req_async_log_file.close()
ft_agent_async_log_file.close()
execute_async_log_file.close()
overall_async_log_file.close()
