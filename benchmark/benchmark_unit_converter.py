#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from logging import getLogger

from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL

logger = getLogger(__name__)

ConverterSnowSQL = SnowflakeConverterSnowSQL


def test_benchmark_date_converter():
    conv = ConverterSnowSQL(support_negative_year=True)
    conv.set_parameter("DATE_OUTPUT_FORMAT", "YY-MM-DD")
    m = conv.to_python_method("DATE", {"scale": 0})
    current_date_counter = 12345
    for _ in range(2000000):
        m(current_date_counter)


def test_benchmark_date_without_negative_converter():
    conv = ConverterSnowSQL(support_negative_year=False)
    conv.set_parameter("DATE_OUTPUT_FORMAT", "YY-MM-DD")
    m = conv.to_python_method("DATE", {"scale": 0})
    current_date_counter = 12345
    for _ in range(2000000):
        m(current_date_counter)


def test_benchmark_timestamp_converter():
    conv = ConverterSnowSQL(support_negative_year=True)
    conv.set_parameter("TIMESTAMP_NTZ_OUTPUT_FORMAT", "YYYY-MM-DD HH24:MI:SS.FF9")
    m = conv.to_python_method("TIMESTAMP_NTZ", {"scale": 9})
    current_timestamp = "2208943503.876543211"
    for _ in range(2000000):
        m(current_timestamp)


def test_benchmark_timestamp_without_negative_converter():
    conv = ConverterSnowSQL(support_negative_year=False)
    conv.set_parameter("TIMESTAMP_NTZ_OUTPUT_FORMAT", "YYYY-MM-DD HH24:MI:SS.FF9")
    m = conv.to_python_method("TIMESTAMP_NTZ", {"scale": 9})
    current_timestamp = "2208943503.876543211"
    for _ in range(2000000):
        m(current_timestamp)
