from __future__ import annotations

import asyncio
import logging
from typing import Callable

from ..time_util import TimerContextManager as TimerContextManagerSync

logger = logging.getLogger(__name__)


class HeartBeatTimer:
    """An asyncio-based timer which executes a function every client_session_keep_alive_heartbeat_frequency seconds."""

    def __init__(
        self, client_session_keep_alive_heartbeat_frequency: int, f: Callable
    ) -> None:
        self.interval = client_session_keep_alive_heartbeat_frequency
        self.function = f
        self._task = None
        self._stopped = asyncio.Event()  # Event to stop the loop

    async def run(self) -> None:
        """Async function to run the heartbeat at regular intervals."""
        try:
            while not self._stopped.is_set():
                await asyncio.sleep(self.interval)
                if not self._stopped.is_set():
                    try:
                        await self.function()
                    except Exception as e:
                        logger.debug("failed to heartbeat: %s", e)
        except asyncio.CancelledError:
            logger.debug("Heartbeat timer was cancelled.")

    async def start(self) -> None:
        """Starts the heartbeat."""
        self._stopped.clear()
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        """Stops the heartbeat."""
        self._stopped.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


class TimerContextManager(TimerContextManagerSync):
    async def __aenter__(self):
        return super().__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return super().__exit__(exc_type, exc_val, exc_tb)
