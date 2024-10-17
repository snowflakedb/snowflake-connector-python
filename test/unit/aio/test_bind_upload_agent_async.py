#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from unittest.mock import AsyncMock


async def test_bind_upload_agent_uploading_multiple_files():
    from snowflake.connector.aio._build_upload_agent import BindUploadAgent

    csr = AsyncMock(auto_spec=True)
    rows = [bytes(10)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    await agent.upload()
    assert csr.execute.call_count == 11  # 1 for stage creation + 10 files


async def test_bind_upload_agent_row_size_exceed_buffer_size():
    from snowflake.connector.aio._build_upload_agent import BindUploadAgent

    csr = AsyncMock(auto_spec=True)
    rows = [bytes(15)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    await agent.upload()
    assert csr.execute.call_count == 11  # 1 for stage creation + 10 files
