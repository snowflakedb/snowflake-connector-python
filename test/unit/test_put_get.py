#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
from os import chmod, path

import pytest
from mock import MagicMock

from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.errors import Error
from snowflake.connector.file_transfer_agent import (
    SnowflakeAzureProgressPercentage,
    SnowflakeFileTransferAgent,
    SnowflakeS3ProgressPercentage,
)

try:
    from snowflake.connector.file_transfer_agent_sdk import (
        SnowflakeFileTransferAgent as SnowflakeFileTransferAgentSDK,
    )
except ImportError:
    from snowflake.connector.file_transfer_agent import (
        SnowflakeFileTransferAgent as SnowflakeFileTransferAgentSDK,
    )


@pytest.mark.skipif(IS_WINDOWS, reason="permission model is different")
def test_put_error(tmpdir, sdkless):
    """Tests for raise_put_get_error flag (now turned on by default) in SnowflakeFileTransferAgent."""
    tmp_dir = str(tmpdir.mkdir("putfiledir"))
    file1 = path.join(tmp_dir, "file1")
    remote_location = path.join(tmp_dir, "remote_loc")
    with open(file1, "w") as f:
        f.write("test1")

    con = MagicMock()
    cursor = con.cursor()
    cursor.errorhandler = Error.default_errorhandler
    query = "PUT something"
    ret = {
        "data": {
            "command": "UPLOAD",
            "autoCompress": False,
            "src_locations": [file1],
            "sourceCompression": "none",
            "stageInfo": {
                "creds": {},
                "location": remote_location,
                "locationType": "LOCAL_FS",
                "path": "remote_loc",
            },
        },
        "success": True,
    }

    agent_class = (
        SnowflakeFileTransferAgent if sdkless else SnowflakeFileTransferAgentSDK
    )

    # no error is raised
    sf_file_transfer_agent = agent_class(cursor, query, ret, raise_put_get_error=False)
    sf_file_transfer_agent.execute()
    sf_file_transfer_agent.result()

    # nobody can read now.
    chmod(file1, 0o000)
    # Permission error should be raised
    sf_file_transfer_agent = agent_class(cursor, query, ret, raise_put_get_error=True)
    sf_file_transfer_agent.execute()
    with pytest.raises(Exception):
        sf_file_transfer_agent.result()

    # unspecified, should fail because flag is on by default now
    sf_file_transfer_agent = agent_class(cursor, query, ret)
    sf_file_transfer_agent.execute()
    with pytest.raises(Exception):
        sf_file_transfer_agent.result()

    chmod(file1, 0o700)


@pytest.mark.skipolddriver
def test_percentage(tmp_path, sdkless):
    """Tests for ProgressPercentage classes."""
    from snowflake.connector.file_transfer_agent import percent

    assert 1.0 == percent(0, 0)
    assert 1.0 == percent(20, 0)
    assert 1.0 == percent(40, 20)
    assert 0.5 == percent(14, 28)

    file_path = tmp_path / "zero_file1"
    file_path.touch()
    func_callback = SnowflakeS3ProgressPercentage(str(file_path), 0)
    func_callback(1)
    func_callback = SnowflakeAzureProgressPercentage(str(file_path), 0)
    func_callback(1)
