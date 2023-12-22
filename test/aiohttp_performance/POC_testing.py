#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
import sys

sys.path.insert(0, "/")

# print(sys.path)

import snowflake.connector.API_async_POC as POC_API


def my_backoff_policy():
    yield 0
    print("Failed once, backing off for 0 seconds")
    yield 1
    print("Failed twice, backing off for 1 seconds")
    yield 2
    print("Failed thrice, backing off for 500 seconds because I feel like it")
    yield 500

    for i in range(5):
        yield 2**i

    raise Exception("I've had enough backing off!")


async def insert_row_with_new_conn(name, gold):
    async with POC_API.SnowflakeConnectionAsyncPOC(
        **{
            "account": "sfctest0",
            "protocol": "https",
            "backoff_policy": my_backoff_policy,
            "ocsp_fail_open": False,
        }
    ) as conn:
        cur = conn.cursor()
        await cur.execute_real_async("USE SCHEMA playground")
        # await cur.execute_real_async("SELECT * FROM player_stats")
        await cur.execute_real_async(
            f"""
            INSERT INTO player_stats (name, gold) values
                ('{name}', {gold})
            ;
        """
        )
        # await cur.execute_real_async(f"select seq4() as foo from table(generator(rowcount=>1000000))")
        print([e async for e in cur])


async def concurrent_inserts_with_new_conn():
    res = await asyncio.gather(
        *[insert_row_with_new_conn(f"player_{i}", 20.5 * i) for i in range(20)]
    )
    print(f"{len(res)} rows inserted with individual connections")


asyncio.run(concurrent_inserts_with_new_conn())


async def insert_row_with_shared_conn(name, gold, conn):
    cur = conn.cursor()
    await cur.execute_real_async("USE SCHEMA playground")
    # await cur.execute_real_async("SELECT * FROM player_stats")
    await cur.execute_real_async(
        f"""
        INSERT INTO player_stats (name, gold) values
            ('{name}', {gold})
        ;
    """
    )
    # await cur.execute_real_async(f"select seq4() as foo from table(generator(rowcount=>1000000))")
    print([e async for e in cur])


async def concurrent_inserts_with_shared_conn():
    async with POC_API.SnowflakeConnectionAsyncPOC(
        **{
            "account": "sfctest0",
            "protocol": "https",
            "backoff_policy": my_backoff_policy,
            "ocsp_fail_open": False,
        }
    ) as conn:
        res = await asyncio.gather(
            *[
                insert_row_with_shared_conn(f"player_{i}", 20.5 * i, conn)
                for i in range(20)
            ]
        )
    print(f"{len(res)} rows inserted with shared connection")


asyncio.run(concurrent_inserts_with_shared_conn())
