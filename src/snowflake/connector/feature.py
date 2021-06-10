#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import os

# Feature flags

feature_use_pyopenssl = True  # use pyopenssl API or openssl command


# use the new code-path without using SDK to put and get files
def feature_sdkless_put() -> bool:
    return os.environ.get("SF_SDKLESS_PUT", "").lower() == "true"


def feature_sdkless_get() -> bool:
    return os.environ.get("SF_SDKLESS_GET", "").lower() == "true"
