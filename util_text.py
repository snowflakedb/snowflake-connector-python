#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import logging
import re

import ijson

COMMENT_PATTERN_RE = re.compile(r'^\s*\-\-')
EMPTY_LINE_RE = re.compile(r'^\s*$')

_logger = logging.getLogger(__name__)


def split_statements(buf, remove_comments=False):
    """
    Splits a stream into SQL statements (ends with a semicolon) or
    commands (!...)
    :param buf: Unicode data stream
    :param remove_comments: True removes all comments
    :return: yields a SQL statement or a command
    """
    in_quote = False
    ch_quote = None
    in_comment = False
    in_double_dollars = False

    line = buf.readline()
    if isinstance(line, bytes):
        raise TypeError("Input data must not be binary type.")

    statement = []
    while line != '':
        col = 0
        col0 = 0
        len_line = len(line)
        while True:
            if col >= len_line:
                if col0 < col:
                    if not in_comment and not in_quote \
                            and not in_double_dollars:
                        statement.append(line[col0:col])
                        if len(statement) == 1 and statement[0] == '':
                            statement = []
                        break
                    elif not remove_comments or in_quote:
                        statement.append(line[col0:col])
                break
            elif in_comment:
                if line[col:].startswith("*/"):
                    in_comment = False
                    if not remove_comments:
                        statement.append(line[col0:col + 2])
                    col += 2
                    col0 = col
                else:
                    col += 1
            elif in_double_dollars:
                if line[col:].startswith("$$"):
                    in_double_dollars = False
                    statement.append(line[col0:col + 2])
                    col += 2
                    col0 = col
                else:
                    col += 1
            elif in_quote:
                if line[col] == ch_quote:
                    if col < len_line - 1 and line[col + 1] != ch_quote or \
                                    col == len_line - 1:
                        # exits quote
                        in_quote = False
                        statement.append(line[col0:col + 1])
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
                elif line[col] in (' ', '\t'):
                    statement.append(line[col0:col + 1])
                    col += 1
                    col0 = col
                elif line[col:].startswith("--"):
                    statement.append(line[col0:col])
                    if not remove_comments:
                        # keep the comment
                        statement.append(line[col:])
                    col = len_line + 1
                    col0 = col
                elif line[col:].startswith("/*") and \
                        not line[col0:].startswith("file://"):
                    if not remove_comments:
                        statement.append(line[col0:col + 2])
                    col += 2
                    col0 = col
                    in_comment = True
                elif line[col:].startswith("$$"):
                    statement.append(line[col0:col + 2])
                    col += 2
                    col0 = col
                    in_double_dollars = True
                elif line[col] == ';':
                    statement.append(line[col0:col + 1])
                    col += 1
                    try:
                        if line[col] == '>':
                            col += 1
                            statement[-1] += '>'
                    except IndexError:
                        pass
                    if COMMENT_PATTERN_RE.match(line[col:]) or \
                            EMPTY_LINE_RE.match(line[col:]):
                        if not remove_comments:
                            # keep the comment
                            statement.append(line[col:])
                        col = len_line
                    while col < len_line and line[col] in (' ', '\t'):
                        col += 1
                    yield ''.join(statement).strip()
                    col0 = col
                    statement = []
                elif col == 0 and line[col] == '!':  # command
                    if len(statement) > 0:
                        yield ''.join(statement).strip()
                        statement = []
                    yield line.rstrip(';').strip()
                    break
                else:
                    col += 1
        line = buf.readline()

    if len(statement) > 0:
        yield ''.join(statement).strip()


def split_rows_from_stream(stream):
    """
    Splits into rows from a stream object. Generator.
    """
    row = []
    in_row = False
    for prefix, event, value in ijson.parse(stream):
        if prefix == '':
            continue
        if in_row:
            if event == 'end_array':
                yield row
                row = []
                in_row = False
            else:
                row.append(value)
        elif event == 'start_array':
            in_row = True
