#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import os
import time

import test_utils

import snowflake.connector as connector
import snowflake.connector.cursor as cursor
import snowflake.connector.file_transfer_agent as file_transfer_agent
import snowflake.connector.network as network
import snowflake.connector.result_batch as result_batch
import snowflake.connector.storage_client as storage_client


def my_backoff_policy():
    yield 0
    raise Exception("WTF WHY DID SOMETHING FAIL?")


fetch_sync_log_file = open(
    "/tmp/aiohttp_test/SnowflakeRestful.fetch.txt", mode="w", buffering=1
)
download_sync_log_file = open(
    "/tmp/aiohttp_test/ResultBatch._download.txt", mode="w", buffering=1
)
storage_req_sync_log_file = open(
    "/tmp/aiohttp_test/SnowflakeStorageClient._send_request_with_retry.txt",
    mode="w",
    buffering=1,
)
ft_agent_sync_log_file = open(
    "/tmp/aiohttp_test/SnowflakeFileTransferAgent.execute.txt", mode="w", buffering=1
)
execute_sync_log_file = open(
    "/tmp/aiohttp_test/execute sync.txt", mode="w", buffering=1
)
overall_sync_log_file = open(
    "/tmp/aiohttp_test/overall sync.txt", mode="w", buffering=1
)

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
        "use_async": False,
    }
)


@test_utils.wrap_function(overall_sync_log_file)
def do_thing(conn, i):
    cur = conn.cursor()
    cur.execute("USE SCHEMA playground")
    # cur.execute("SELECT * FROM player_stats")
    # cur.execute("CALL SYSTEM$WAIT(1);")
    # cur.execute(f"select seq4() as foo from table(generator(rowcount=>1000000))")
    # cur.execute(f"GET @%player_stats file:///tmp/sync_{i}")
    cur.execute("REMOVE @%player_stats")
    cur.execute("PUT file:///tmp/OGABOGA.txt.gz @%player_stats")
    _ = [e for e in cur]


test_utils.wrap_method_with_timer(
    network.SnowflakeRestful, "fetch", fetch_sync_log_file
)
test_utils.wrap_method_with_timer(
    result_batch.ResultBatch, "_download", download_sync_log_file
)
test_utils.wrap_method_with_timer(
    storage_client.SnowflakeStorageClient,
    "_send_request_with_retry",
    storage_req_sync_log_file,
)
test_utils.wrap_method_with_timer(
    file_transfer_agent.SnowflakeFileTransferAgent, "execute", ft_agent_sync_log_file
)
test_utils.wrap_method_with_timer(
    cursor.SnowflakeCursor, "execute", execute_sync_log_file
)
for i in range(25):
    # try:
    #     os.mkdir(f"/tmp/sync_{i}")
    # except:
    #     pass
    print(i)
    do_thing(conn, i)
    time.sleep(0.1)

fetch_sync_log_file.close()
download_sync_log_file.close()
storage_req_sync_log_file.close()
ft_agent_sync_log_file.close()
execute_sync_log_file.close()
overall_sync_log_file.close()
