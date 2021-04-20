#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from antlr4 import CommonTokenStream, InputStream, ParseTreeWalker

from snowflake.connector.antlr.querySeparatorLexer import querySeparatorLexer
from snowflake.connector.antlr.querySeparatorListener import querySeparatorListener
from snowflake.connector.antlr.querySeparatorParser import querySeparatorParser


class sfcliSeparatorParser(querySeparatorParser):
    def anonymousBlock(self):
        querySeparatorParser.anonymousBlock(self)

    def createFunctionStatement(self):
        querySeparatorParser.createFunctionStatement(self)

    def normalStatements(self):
        querySeparatorParser.normalStatements(self)


class sfSqlSeparatorListener(querySeparatorListener):
    """ use client side mini parser querySeparatorParser to split statements. """

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
            self.result.append(
                [
                    -1 if ctx.start is None else ctx.start.start,
                    -1 if ctx.stop is None else ctx.stop.stop,
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


def sep_sqls(sqltext: str):
    sqltext = sqltext.strip()
    sqlstream = InputStream(sqltext)

    lexer = querySeparatorLexer(sqlstream)
    tokens = CommonTokenStream(lexer)
    parser = sfcliSeparatorParser(tokens)
    tree = parser.queriesText()

    listener = sfSqlSeparatorListener()
    ParseTreeWalker.DEFAULT.walk(listener, tree)

    stmt_list = []
    for stmtpos in listener.result:
        stmt_list.append(sqltext[stmtpos[0] : stmtpos[1] + 1])

    return stmt_list
