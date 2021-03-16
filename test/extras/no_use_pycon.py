#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

# This test tests for SNOW-186747
import requests

import snowflake.connector  # NOQA

r = requests.get(
    "https://snowflake.com/", headers={"User-Agent": ""}, allow_redirects=False
)
assert r.status_code == 301
