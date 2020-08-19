#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from .converter import SnowflakeConverter


class SnowflakeNoConverterToPython(SnowflakeConverter):
    def __init__(self, **kwargs):
        super(SnowflakeNoConverterToPython, self).__init__(**kwargs)

    def to_python_method(self, type_name, column):
        return None
