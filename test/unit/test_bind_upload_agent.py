#!/usr/bin/env python
from __future__ import annotations

from unittest import mock
from unittest.mock import MagicMock


def test_bind_upload_agent_uploading_multiple_files():
    from snowflake.connector.bind_upload_agent import BindUploadAgent

    csr = MagicMock(auto_spec=True)
    rows = [bytes(10)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    agent.upload()
    assert csr.execute.call_count == 11  # 1 for stage creation + 10 files


def test_bind_upload_agent_row_size_exceed_buffer_size():
    from snowflake.connector.bind_upload_agent import BindUploadAgent

    csr = MagicMock(auto_spec=True)
    rows = [bytes(15)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    agent.upload()
    assert csr.execute.call_count == 11  # 1 for stage creation + 10 files


def test_bind_upload_agent_scoped_temp_object():
    from snowflake.connector.bind_upload_agent import BindUploadAgent

    csr = MagicMock(auto_spec=True)
    rows = [bytes(15)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    with mock.patch.object(agent, "_use_scoped_temp_object", new=True):
        with mock.patch.object(agent.cursor, "execute") as mock_execute:
            agent._create_stage()
            assert (
                "create or replace SCOPED TEMPORARY stage"
                in mock_execute.call_args[0][0]
            )
