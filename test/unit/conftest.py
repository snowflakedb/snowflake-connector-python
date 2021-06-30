#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os

import pytest


@pytest.fixture(
    params=[pytest.param(True, marks=pytest.mark.skipolddriver), False],
    ids=["sdkless", "sdkfull"],
)
def sdkless(request):
    if request.param:
        os.environ["SF_SDKLESS_PUT"] = "true"
        os.environ["SF_SDKLESS_GET"] = "true"
    else:
        os.environ["SF_SDKLESS_PUT"] = "false"
        os.environ["SF_SDKLESS_GET"] = "false"
    return request.param
