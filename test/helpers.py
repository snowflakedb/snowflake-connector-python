#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from mock import Mock

from snowflake.connector.compat import OK


def create_mock_response(status_code: int) -> Mock:
    """Create a Mock "Response" with a given status code. See `test_result_batch.py` for examples.
    Args:
        status_code: the status code of the response.
    Returns:
        A Mock object that can be used as a Mock Response in tests.
    """
    mock_resp = Mock()
    mock_resp.status_code = status_code
    mock_resp.raw = "success" if status_code == OK else "fail"
    return mock_resp
