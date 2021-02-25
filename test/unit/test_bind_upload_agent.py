#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import pytest
from mock import MagicMock


@pytest.mark.skipolddriver
def test_bind_upload_agent_upload_multiple_files():
    from snowflake.connector.bind_upload_agent import BindUploadAgent
    csr = MagicMock(auto_spec=True)
    rows = [bytes(10)] * 10
    agent = BindUploadAgent(csr, rows, stream_buffer_size=10)
    agent.upload()
    assert csr.execute.call_count == 11  # 1 for stage creation + 10 files
