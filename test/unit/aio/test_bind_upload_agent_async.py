#!/usr/bin/env python


from __future__ import annotations

from unittest.mock import AsyncMock


async def test_bind_upload_agent_uploading_multiple_files():
    from snowflake.connector.aio._bind_upload_agent import BindUploadAgent

    csr = AsyncMock(auto_spec=True)
    rows = [bytes(10)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    await agent.upload()
    assert csr.execute.call_count == 1  # 1 for stage creation
    assert csr._upload_stream.call_count == 10  # 10 for 10 files


async def test_bind_upload_agent_row_size_exceed_buffer_size():
    from snowflake.connector.aio._bind_upload_agent import BindUploadAgent

    csr = AsyncMock(auto_spec=True)
    rows = [bytes(15)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    await agent.upload()
    assert csr.execute.call_count == 1  # 1 for stage creation
    assert csr._upload_stream.call_count == 10  # 10 for 10 files
