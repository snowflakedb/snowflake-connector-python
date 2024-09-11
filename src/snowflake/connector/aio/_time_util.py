#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from ..time_util import TimerContextManager as TimerContextManagerSync


class TimerContextManager(TimerContextManagerSync):
    async def __aenter__(self):
        return super().__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return super().__exit__(exc_type, exc_val, exc_tb)
