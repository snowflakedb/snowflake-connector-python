#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import time
from threading import Lock, Thread
from typing import Any, Coroutine

import nest_asyncio

# !!!READ ME!!!

# You must call event_loop_runner.start before using event_loop_runner.LOOP_RUNNER

# event_loop_runner.start should be called ONCE, before the program starts
# event_loop_runner.stop should be called ONCE, after the program ends

# You MUST do this if you are using SnowflakeConnection with use_async set to True

# !!!READ ME!!!

# YICHUAN: Consider the situation where a client uses the Python Connector with use_async set to True from their async
# code where an event loop is already running
# In this situation, we cannot use asyncio.run for sync wrappers as asyncio event loops are not meant to be nested
# (formally, they are not reentrant)

# Furthermore, because we cache asyncio.ClientSessions using sessions_map in SnowflakeRestfulAsync, asyncio.run may
# inadvertently close the event loop that sessions need after completing a request, preventing its reuse
# Thus, we need a way to manage an event loop ourselves, and use it to run async methods instead of relying on asyncio
# to do it for us

# A simple solution is to get a loop via asyncio.get_event_loop, then run async methods using run_until_complete_safe,
# which uses nest_asyncio to make the loop reentrant even if it is already running due to client async code
# The problem with this solution is that it breaks SnowflakeStorageClientAsync, which uses SnowflakeRestfulAsync and
# its event loop from multiple threads


# A more robust solution is to have a separate thread host the event loop, running indefinitely, and any async work can
# be shipped off to that thread
# This way, we have a reliable, isolated event loop for our sync wrappers that won't interact badly with anything, and
# still gives us the advantage of async concurrency when multiple threads are performing I/O bound async operations


# The EventLoopThreadRunner hosted in this module will be shared by all async methods in the Python Connector that need
# a sync wrapper which, once again, is good because we can have all async tasks running on an event loop
class EventLoopThreadRunner:
    def __init__(self) -> None:
        self._loop: asyncio.BaseEventLoop = asyncio.new_event_loop()
        self._thread: Thread = Thread(
            target=lambda loop: loop.run_forever(), args=(self._loop,)
        )
        self._running = False

    @property
    def loop(self) -> asyncio.BaseEventLoop:
        if not self._running:
            raise Exception("Runner is not running and has no running loop")

        return self._loop

    def _start(self) -> None:
        if self._running:
            raise Exception("Running is already running")

        self._thread.start()

        # YICHUAN: Wait for event loop to actually start so no coroutines are run while thread is still working, this
        # is a bit hacky but there's not much else we can do about it
        while not self._loop.is_running():
            time.sleep(0.1)

        self._running = True

    def _stop(self) -> None:
        if not self._running:
            raise Exception("Runner is already stopped")

        # YICHUAN: IT IS NOT SAFE TO ATTEMPT TO CLOSE A LOOP FROM ANOTHER (main) THREAD
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        # YICHUAN: Close loop AFTER the join to ensure that the thread has already stopped the loop
        self._loop.close()

        if self._thread.is_alive():
            raise Exception("Failed to stop runner thread")

        self._running = False

    def run_coro(self, coro: Coroutine) -> Any:
        if not self._running:
            raise Exception(f"Runner not running and cannot run coroutine: {coro}")

        res = asyncio.run_coroutine_threadsafe(coro, loop=self._loop)
        # YICHUAN: Waiting for the result will block, which is what we want for a sync wrapper
        return res.result()


# YICHUAN: CURRENTLY UNUSED, see EventLoopThreadRunner and explanation above
def run_until_complete_safe(loop, coro) -> Any:
    if loop.is_running():
        # YICHUAN: Patching a loop multiple times is safe
        nest_asyncio.apply(loop)
    return loop.run_until_complete(coro)


STATE_LOCK: Lock = Lock()
LOOP_RUNNER: EventLoopThreadRunner = EventLoopThreadRunner()


def start() -> None:
    global STATE_LOCK, LOOP_RUNNER
    with STATE_LOCK:
        LOOP_RUNNER._start()


def stop() -> None:
    global STATE_LOCK, LOOP_RUNNER
    with STATE_LOCK:
        LOOP_RUNNER._stop()
