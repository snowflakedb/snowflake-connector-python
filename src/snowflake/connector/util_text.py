#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import logging
from io import StringIO

from .antlr.sql_separator import sep_sqls

_logger = logging.getLogger(__name__)


def is_put_or_get(stmt):
    return stmt[:3].upper() in ("PUT", "GET")


def split_statements(
    buf: StringIO,
):
    sqltext = buf.read()
    stmts = sep_sqls(sqltext)
    for stmt in stmts:
        yield stmt, is_put_or_get(stmt)


def construct_hostname(region, account):
    """Constructs hostname from region and account."""
    if region == "us-west-2":
        region = ""
    if region:
        if account.find(".") > 0:
            account = account[0 : account.find(".")]
        host = "{}.{}.snowflakecomputing.com".format(account, region)
    else:
        host = "{}.snowflakecomputing.com".format(account)
    return host


def parse_account(account):
    url_parts = account.split(".")
    # if this condition is true, then we have some extra
    # stuff in the account field.
    if len(url_parts) > 1:
        if url_parts[1] == "global":
            # remove external ID from account
            parsed_account = url_parts[0][0 : url_parts[0].rfind("-")]
        else:
            # remove region subdomain
            parsed_account = url_parts[0]
    else:
        parsed_account = account

    return parsed_account
