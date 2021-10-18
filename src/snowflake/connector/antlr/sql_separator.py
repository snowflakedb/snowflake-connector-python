#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from antlr4 import CommonTokenStream, InputStream, ParseTreeWalker

from .querySeparatorLexer import querySeparatorLexer
from .querySeparatorListener import querySeparatorListener
from .querySeparatorParser import querySeparatorParser

COMMENT_CHANNEL: int = 9


def is_put_or_get(stmt):
    return stmt.strip()[:3].upper() in ("PUT", "GET")


def is_comment_rest_line(comment: str):
    compact = comment.strip()
    if compact.startswith("--") or compact.startswith("//"):
        return True
    return False


class sfcliSeparatorParser(querySeparatorParser):
    def anonymousBlock(self):
        querySeparatorParser.anonymousBlock(self)

    def createFunctionStatement(self):
        querySeparatorParser.createFunctionStatement(self)

    def normalStatements(self):
        querySeparatorParser.normalStatements(self)


class sfSqlSeparatorListener(querySeparatorListener):
    """use client side mini parser querySeparatorParser to split statements."""

    def __init__(self):
        self.result = []
        self.result_str = []
        self.level = 0
        self.blockLevel = 0
        self.result_blocks = []

    def enterStatement(self, ctx: querySeparatorParser.StatementContext):
        self.level += 1

    # Exit a parse tree produced by querySeparatorParser#statement.
    def exitStatement(self, ctx: querySeparatorParser.StatementContext):
        self.level -= 1
        if self.level == 0:
            last_tok = ctx.stop
            self.result.append(
                [
                    -1 if ctx.start is None else ctx.start.start,
                    -1 if ctx.stop is None else ctx.stop.stop,
                    -1
                    if last_tok is None
                    else last_tok.line,  # for same line comment attaching backward compatibility
                ]
            )

            self.result_str.append(ctx.getText())

    # Enter a parse tree produced by querySeparatorParser#anonymousBlock.
    def enterAnonymousBlock(self, ctx: querySeparatorParser.AnonymousBlockContext):
        self.blockLevel += 1

    # Exit a parse tree produced by querySeparatorParser#anonymousBlock.
    def exitAnonymousBlock(self, ctx: querySeparatorParser.AnonymousBlockContext):
        self.blockLevel -= 1
        if self.blockLevel == 0:
            self.result_blocks.append([ctx.start.start, ctx.stop.stop])


def sep_sqls(
    sqltext: str,
    remove_comments: bool = False,
):
    """separate sql scripts
    input:
      sqltext - the sql script string
      remove_comments - whether to remove comments in sql script
     return:
       stmt_list: list of statements
       is_put_get: list of boolean. About if stmt_list[i] is PUT/GET command
    """
    sqltext = sqltext.strip()
    sqlstream = InputStream(sqltext)

    lexer = querySeparatorLexer(sqlstream)
    token_stream = CommonTokenStream(lexer)

    parser = sfcliSeparatorParser(token_stream)
    tree = parser.queriesText()

    listener = sfSqlSeparatorListener()
    ParseTreeWalker.DEFAULT.walk(listener, tree)

    stmt_list = []
    is_put_get = []

    line_comment_map = {}

    comment_num = 0
    comment_toks = []
    for tok in token_stream.tokens:
        if tok.channel == COMMENT_CHANNEL:
            comment_num += 1
            comment_toks.append(tok)
            if line_comment_map.get(tok.line) is None:
                line_comment_map[tok.line] = []
            line_comment_map[tok.line].append(tok)
    # the trivial case when there is no comment at all. No extra code/logic is needed
    if comment_num == 0:
        for stmtpos in listener.result:
            trimed_stmt = sqltext[stmtpos[0] : stmtpos[1] + 1]
            stmt_list.append(trimed_stmt)
            is_put_get.append(is_put_or_get(trimed_stmt))

        return stmt_list, is_put_get

    if remove_comments:
        # we have the begin and end positions of statements,
        # now remove the comments inside statements.
        sorted(comment_toks, key=lambda tok: tok.start)

        cur_idx = 0
        for stmtpos in listener.result:
            cur = stmtpos[0]
            stmt_stop = stmtpos[1]
            trimed_stmt = ""

            while cur_idx < comment_num and comment_toks[cur_idx].start < stmt_stop:
                # skip comments that starts before current statement.
                if comment_toks[cur_idx].stop < stmtpos[0]:
                    cur_idx += 1
                    continue
                # hit one comment inside statement, add the statement string before this comment.
                trimed_stmt += sqltext[cur : comment_toks[cur_idx].start]
                cur = comment_toks[cur_idx].stop + 1
                if cur < len(sqltext) and sqltext[cur - 1] == "\n":
                    cur -= 1
                cur_idx += 1

            if cur < stmt_stop:
                trimed_stmt += sqltext[cur : stmt_stop + 1]

            stmt_list.append(trimed_stmt)
            is_put_get.append(is_put_or_get(trimed_stmt))
    else:
        # when we don't need to remove comments.
        # here is to simulate how the old way of splitting
        # attach comments with last or next statement:
        #   we already have begin and end positions of a statement,
        #    -- only the comment begins with '--' and '//' on the same line
        #      that immediately follows the statement will go with this (prev) statement,
        #    -- other comments go with next statement, unless it is the last statement.
        # TODO: To be simplified once we don't have to keep identical output with old code

        result_num = len(listener.result)
        start = 0
        for idx in range(result_num):
            stmtpos = listener.result[idx]
            end = stmtpos[1]
            # there are comments on the same line of last token of the statement.
            if line_comment_map.get(stmtpos[2]) is not None:
                for line_comm in line_comment_map.get(stmtpos[2]):
                    # Handle the first comment After the statement then break.
                    if line_comm.start > end:
                        if is_comment_rest_line(line_comm.text):
                            end = line_comm.stop
                        break
            elif idx == (result_num - 1):
                end = len(sqltext)

            stmt_list.append(sqltext[start : end + 1])
            start = end + 1

        assert len(stmt_list) == len(listener.result)
        for stmtpos in listener.result:
            is_put_get.append(is_put_or_get(sqltext[stmtpos[0] : stmtpos[1]]))

    return stmt_list, is_put_get
