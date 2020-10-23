#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging

from snowflake.connector.gcs_util import SnowflakeGCSUtil


def test_create_client(caplog):
    """Creates a GCSUtil with an access token."""
    client = SnowflakeGCSUtil.create_client({'creds': {'GCS_ACCESS_TOKEN': 'fake_token'}})
    assert client is None
    assert caplog.record_tuples == [
        ('snowflake.connector.gcs_util', logging.DEBUG, "len(GCS_ACCESS_TOKEN): 10"),
        ('snowflake.connector.gcs_util', logging.DEBUG, "GCS operations with an access token are currently unsupported")
    ]
