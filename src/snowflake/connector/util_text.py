#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import logging
import re
from io import StringIO
from typing import Optional

from .antlr.sql_separator import is_put_or_get, sep_sqls

_logger = logging.getLogger(__name__)

# the pattern match a full line of comment
SF_COMMENT_CMD_PATTERN = re.compile(r"(\n|\r)+\s*--sf:.+(\n|\r)+")

RE_SPLIT_OFF = re.compile(r"(\n|\r)+\s*--sf:\s*auto_split\s+off")

RE_BEGIN_BLOCK = re.compile(r"(\n|\r)+\s*--sf:\s*<<\s*(\n|\r)+")

RE_END_BLOCK = re.compile(r"(\n|\r)+\s*--sf:\s*>>\s*(\n|\r)+")

RE_SEPARATOR = re.compile(r"(\n|\r)+\s*--sf:\s*<<>>\s*(\n|\r)+")


class SQLDelimiter(object):
    """Class that wraps a SQL delimiter string.

    Since split_statements is a generator this mutable object will allow it change while executing.
    """

    def __str__(self):
        return self.sql_delimiter

    def __init__(self, sql_delimiter: str = ";"):
        """Initializes SQLDelimiter with a string."""
        self.sql_delimiter = sql_delimiter


def split_statements(
    buf: StringIO,
    remove_comments: bool = False,
    delimiter: Optional[SQLDelimiter] = None,
):
    """Entry function to split statements."""
    if delimiter is None or str(delimiter) == ";":
        return split_statements_new(buf, remove_comments)
    else:
        return split_statements_old(buf, remove_comments, delimiter)


def split_statements_new(
    buf: StringIO,
    remove_comments: bool = False,
):
    """split_statements_new is not taking delimiter.
    This new method tries to use a mini ANTLR parser to recognize SQL statement blocks, especially
    'create procedure...begin .. end'
    In this method, users could also use manual way to guide the splitting
    by using special comments. A pure comment line '--SF:<snowflake splitting hints>'
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
    for m in SF_COMMENT_CMD_PATTERN.finditer(sqltext.lower()):
        sfcmds.append([m.start(), m.end()])

    # stmts to store the split result to return
    stmts = []
    is_put_get = []
    is_auto_split = True

    sqltext_lower = sqltext.lower()
    for cmd in sfcmds:
        if is_auto_split and RE_SPLIT_OFF.match(sqltext_lower, cmd[0], cmd[1]):
            _logger.info("auto_split off")
            is_auto_split = False
    starting_pos_of_block = -1  # not in block yet
    last_pos = 0  # last pos of ending blocks

    # pieces contains tuples [(0|1, str)].
    # 0 means the string could be split, 1 means it is a whole block
    pieces = []

    for cmd in sfcmds:
        if starting_pos_of_block < 0 and RE_BEGIN_BLOCK.match(
            sqltext_lower, cmd[0], cmd[1]
        ):
            starting_pos_of_block = cmd[1]
            pieces.append([0, sqltext[last_pos : (cmd[0])]])
        elif starting_pos_of_block > 0 and RE_END_BLOCK.match(
            sqltext_lower, cmd[0], cmd[1]
        ):
            pieces.append([1, sqltext[starting_pos_of_block : (cmd[0])]])
            last_pos = cmd[1]
            starting_pos_of_block = -1
        elif starting_pos_of_block < 0 and RE_SEPARATOR.match(
            sqltext_lower, cmd[0], cmd[1]
        ):
            pieces.append([0, sqltext[last_pos : (cmd[0])]])
            last_pos = cmd[1]

    if last_pos < len(sqltext):
        pieces.append([0, sqltext[last_pos:]])

    if not is_auto_split:
        stmts = [p[1].strip() for p in pieces]
        is_put_get = [is_put_or_get(stmt) for stmt in stmts]
    else:  # now apply auto-split to the pieces that were not wrapped by << and >> (piece[0]==1)
        for piece in pieces:
            if piece[0] == 0:
                new_stmts, ret_is_put_get = sep_sqls(piece[1], remove_comments)
                for idx in range(len(new_stmts)):
                    stmts.append(new_stmts[idx].strip())
                    is_put_get.append(ret_is_put_get[idx])

            elif piece[0] == 1:
                stmt = piece[1].strip()
                stmts.append(stmt)
                is_put_get.append(is_put_or_get(stmt))

    for i in range(len(stmts)):
        yield stmts[i], is_put_get[i]


#
# Below is the old way of splitting statements which allows delimiter
# and does not support blocks(begin..end) and 'create procedure'
#

COMMENT_PATTERN_RE = re.compile(r"^\s*\-\-")
EMPTY_LINE_RE = re.compile(r"^\s*$")

_logger = logging.getLogger(__name__)


def split_statements_old(
    buf: StringIO,
    remove_comments: bool = False,
    delimiter: Optional[SQLDelimiter] = None,
):
    """Splits a stream into SQL statements (ends with a semicolon) or commands (!...).

    Args:
        buf: Unicode data stream.
        remove_comments: Whether or not to remove all comments (Default value = False).
        delimiter: The delimiter string that separates SQL commands from each other.

    Yields:
        A SQL statement or a command.
    """
    if delimiter is None:
        delimiter = SQLDelimiter()  # Use default delimiter if none was given.
    in_quote = False
    ch_quote = None
    in_comment = False
    in_double_dollars = False
    previous_delimiter = None

    line = buf.readline()
    if isinstance(line, bytes):
        raise TypeError("Input data must not be binary type.")

    statement = []
    while line != "":
        col = 0
        col0 = 0
        len_line = len(line)
        sql_delimiter = delimiter.sql_delimiter
        if not previous_delimiter or sql_delimiter != previous_delimiter:
            # Only (re)compile new Regexes if they should be
            escaped_delim = re.escape(sql_delimiter)
            # Special characters possible in the sql delimiter are '_', '/' and ';'. If a delimiter does not end, or
            # start with a special character then look for word separation with \b regex.
            if re.match(r"\w", sql_delimiter[0]):
                RE_START = re.compile(r"^[^\w$]?{}".format(escaped_delim))
            else:
                RE_START = re.compile(r"^.?{}".format(escaped_delim))
            if re.match(r"\w", sql_delimiter[-1]):
                RE_END = re.compile(r"{}[^\w$]?$".format(escaped_delim))
            else:
                RE_END = re.compile(r"{}.?$".format(escaped_delim))
            previous_delimiter = sql_delimiter
        while True:
            if col >= len_line:
                if col0 < col:
                    if not in_comment and not in_quote and not in_double_dollars:
                        statement.append((line[col0:col], True))
                        if len(statement) == 1 and statement[0][0] == "":
                            statement = []
                        break
                    elif not in_comment and (in_quote or in_double_dollars):
                        statement.append((line[col0:col], True))
                    elif not remove_comments:
                        statement.append((line[col0:col], False))
                break
            elif in_comment:
                if line[col:].startswith("*/"):
                    in_comment = False
                    if not remove_comments:
                        statement.append((line[col0 : col + 2], False))
                    col += 2
                    col0 = col
                else:
                    col += 1
            elif in_double_dollars:
                if line[col:].startswith("$$"):
                    in_double_dollars = False
                    statement.append((line[col0 : col + 2], False))
                    col += 2
                    col0 = col
                else:
                    col += 1
            elif in_quote:
                if (
                    line[col] == "\\"
                    and col < len_line - 1
                    and line[col + 1] in (ch_quote, "\\")
                ):
                    col += 2
                elif line[col] == ch_quote:
                    if (
                        col < len_line - 1
                        and line[col + 1] != ch_quote
                        or col == len_line - 1
                    ):
                        # exits quote
                        in_quote = False
                        statement.append((line[col0 : col + 1], True))
                        col += 1
                        col0 = col
                    else:
                        # escaped quote and still in quote
                        col += 2
                else:
                    col += 1
            else:
                if line[col] in ("'", '"'):
                    in_quote = True
                    ch_quote = line[col]
                    col += 1
                elif line[col] in (" ", "\t"):
                    statement.append((line[col0 : col + 1], True))
                    col += 1
                    col0 = col
                elif line[col:].startswith("--"):
                    statement.append((line[col0:col], True))
                    if not remove_comments:
                        # keep the comment
                        statement.append((line[col:], False))
                    col = len_line + 1
                    col0 = col
                elif line[col:].startswith("/*") and not line[col0:].startswith(
                    "file://"
                ):
                    if not remove_comments:
                        statement.append((line[col0 : col + 2], False))
                    else:
                        statement.append((line[col0:col], False))
                    col += 2
                    col0 = col
                    in_comment = True
                elif line[col:].startswith("$$"):
                    statement.append((line[col0 : col + 2], True))
                    col += 2
                    col0 = col
                    in_double_dollars = True
                elif (
                    RE_START.match(line[col - 1 : col + len(sql_delimiter)])
                    if col > 0
                    else (RE_START.match(line[col : col + len(sql_delimiter)]))
                ) and (RE_END.match(line[col : col + len(sql_delimiter) + 1])):
                    statement.append((line[col0:col] + ";", True))
                    col += len(sql_delimiter)
                    try:
                        if line[col] == ">":
                            col += 1
                            statement[-1] = (statement[-1][0] + ">", statement[-1][1])
                    except IndexError:
                        pass
                    if COMMENT_PATTERN_RE.match(line[col:]) or EMPTY_LINE_RE.match(
                        line[col:]
                    ):
                        if not remove_comments:
                            # keep the comment
                            statement.append((line[col:], False))
                        col = len_line
                    while col < len_line and line[col] in (" ", "\t"):
                        col += 1
                    yield _concatenate_statements(statement)
                    col0 = col
                    statement = []
                elif col == 0 and line[col] == "!":  # command
                    if len(statement) > 0:
                        yield _concatenate_statements(statement)
                        statement = []
                    yield (
                        line.strip()[: -len(sql_delimiter)]
                        if line.strip().endswith(sql_delimiter)
                        else line.strip()
                    ).strip(), False
                    break
                else:
                    col += 1
        line = buf.readline()

    if len(statement) > 0:
        yield _concatenate_statements(statement)


def _concatenate_statements(statement_list):
    """Concatenate statements.

    Each statement should be a tuple of statement and is_put_get.

    The is_put_get is set to True if the statement is PUT or GET otherwise False for valid statement.
    None is set if the statement is empty or comment only.

    Args:
        statement_list: List of statement parts.

    Returns:
        Tuple of statements and whether they are PUT or GET.
    """
    valid_statement_list = []
    is_put_get = None
    for text, is_statement in statement_list:
        valid_statement_list.append(text)
        if is_put_get is None and is_statement and len(text.strip()) >= 3:
            is_put_get = text[:3].upper() in ("PUT", "GET")
    return "".join(valid_statement_list).strip(), is_put_get


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
