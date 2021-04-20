#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import logging
import re
from io import StringIO

from .antlr.sql_separator import sep_sqls

_logger = logging.getLogger(__name__)

# the pattern match a full line of comment
sf_comment_cmd_pattern = re.compile(r"(\n|\r)+\s*--sf:.+(\n|\r)+")


def is_put_or_get(stmt):
    return stmt.strip()[:3].upper() in ("PUT", "GET")


def split_statements(
    buf: StringIO,
):
    """For automatic split, sep_sqls(sql) will detect the boundaries of sql statement blocks
    using a simplified ANTLR4 parser. Or users could use manual way to guide the splitting
    by using special comment. A pure comment line '--SF:<snowflake splitting hints>'
    All these commands should not be nested
      (1) '--SF:auto_split off': disable auto split. This should be first cmd in a script file
      (2) to disable split the sql texts between these two hints
      '--SF:<<'
         ...
      '--SF:>>'
      (3) to split the blocks before and after this comment '--SF:<<>>'
    """
    sqltext = buf.read()
    sfcmds = []
    for m in sf_comment_cmd_pattern.finditer(sqltext.lower()):
        sfcmds.append([m.start(), m.end()])

    # stmts to store the split result to return
    stmts = []

    is_auto_split = True

    for cmd in sfcmds:
        if is_auto_split and re.match(
            r"(\n|\r)+\s*--sf:\s*auto_split\s+off", sqltext[cmd[0] : cmd[1]].lower()
        ):
            _logger.info("auto_split off")
            is_auto_split = False
    starting_pos_of_block = -1  # not in block yet
    last_pos = 0  # last pos of ending blocks
    pieces = []
    for cmd in sfcmds:
        if starting_pos_of_block < 0 and re.match(
            r"(\n|\r)+\s*--sf:\s*<<\s*(\n|\r)+", sqltext[cmd[0] : cmd[1]].lower()
        ):
            starting_pos_of_block = cmd[1]
            pieces.append([0, sqltext[last_pos : (cmd[0])]])
        elif starting_pos_of_block > 0 and re.match(
            r"(\n|\r)+\s*--sf:\s*>>\s*(\n|\r)+", sqltext[cmd[0] : cmd[1]].lower()
        ):
            pieces.append([1, sqltext[starting_pos_of_block : (cmd[0])]])
            last_pos = cmd[1]
            starting_pos_of_block = -1
        elif starting_pos_of_block < 0 and re.match(
            r"(\n|\r)+\s*--sf:\s*<<>>\s*(\n|\r)+", sqltext[cmd[0] : cmd[1]].lower()
        ):
            pieces.append([0, sqltext[last_pos : (cmd[0])]])
            last_pos = cmd[1]

    if last_pos < len(sqltext):
        pieces.append([0, sqltext[last_pos:]])

    if not is_auto_split:
        stmts = [p[1].strip() for p in pieces]
    else:  # now apply auto-split to the pieces that were not wrapped by << and >> (piece[0]==1)
        for piece in pieces:
            if piece[0] == 0:
                new_stmts = sep_sqls(piece[1])
                for stmt in new_stmts:
                    stmts.append(stmt.strip())
            elif piece[0] == 1:
                stmts.append(piece[1].strip())

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
