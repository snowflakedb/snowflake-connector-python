#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

from os import chmod, path

import pytest
from mock import MagicMock

from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.errors import Error
from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent


@pytest.mark.skipif(IS_WINDOWS, reason='permission model is different')
def test_put_error(tmpdir):
    """Tests for raise_put_get_error flag (now turned on by default) in SnowflakeFileTransferAgent."""
    tmp_dir = str(tmpdir.mkdir('putfiledir'))
    file1 = path.join(tmp_dir, 'file1')
    remote_location = path.join(tmp_dir, 'remote_loc')
    with open(file1, 'w') as f:
        f.write('test1')

    # nobody can read now.
    chmod(file1, 0o000)

    con = MagicMock()
    cursor = con.cursor()
    cursor.errorhandler = Error.default_errorhandler
    query = 'PUT something'
    ret = {
        'data': {
            'command': 'UPLOAD',
            'autoCompress': False,
            'src_locations': [file1],
            'sourceCompression': 'none',
            'stageInfo': {
                'location': remote_location,
                'locationType': 'LOCAL_FS',
                'path': 'remote_loc',
            }
        },
        'success': True,
    }

    # no error is raised
    sf_file_transfer_agent = SnowflakeFileTransferAgent(
        cursor,
        query,
        ret,
        raise_put_get_error=False)
    sf_file_transfer_agent.execute()
    sf_file_transfer_agent.result()

    # Permission error should be raised
    sf_file_transfer_agent = SnowflakeFileTransferAgent(
        cursor,
        query,
        ret,
        raise_put_get_error=True)
    sf_file_transfer_agent.execute()
    with pytest.raises(Exception):
        sf_file_transfer_agent.result()

    # unspecified, should fail because flag is on by default now
    sf_file_transfer_agent = SnowflakeFileTransferAgent(
        cursor,
        query,
        ret)
    sf_file_transfer_agent.execute()
    with pytest.raises(Exception):
        sf_file_transfer_agent.result()

    chmod(file1, 0o700)
