#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
from io import StringIO

import pytest

from snowflake.connector.compat import PY2
from snowflake.connector.util_text import split_statements


def _to_unicode(sql):
    return sql.decode('utf-8') if PY2 and isinstance(sql, str) else sql


def test_simple_sql():
    with StringIO(_to_unicode("show tables")) as f:
        itr = split_statements(f)
        assert next(itr) == ('show tables', False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("show tables;")) as f:
        itr = split_statements(f)
        assert next(itr) == ('show tables;', False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("select 1;select 2")) as f:
        itr = split_statements(f)
        assert next(itr) == ('select 1;', False)
        assert next(itr) == ('select 2', False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("select 1;select 2;")) as f:
        itr = split_statements(f)
        assert next(itr) == ('select 1;', False)
        assert next(itr) == ('select 2;', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = "select 1; -- test"
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == ('select 1; -- test', False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select 1;', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = "select /* test */ 1; -- test comment select 1;"
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment select 1;', False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;', False)
        with pytest.raises(StopIteration):
            next(itr)


def test_multiple_line_sql():
    s = """select /* test */ 1; -- test comment
select 23;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            ('select /* test */ 1; -- test comment', False))
        assert next(itr) == ('select 23;', False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;', False)
        assert next(itr) == ('select 23;', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; -- test comment 2"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment', False)
        assert next(itr) == ('select 23; -- test comment 2', False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;', False)
        assert next(itr) == ('select 23;', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2 */ select 3"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment', False)
        assert next(itr) == ('select 23;', False)
        assert next(itr) == ('/* test comment 2 */ select 3', False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;', False)
        assert next(itr) == ('select 23;', False)
        assert next(itr) == ('select 3', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2
*/ select 3;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select /* test */ 1; -- test comment", False)
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("/* test comment 2\n*/ select 3;", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select  1;", False)
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("select 3;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test
    continued comments 1
    continued comments 2
    */ 1; -- test comment
select 23; /* test comment 2
*/ select 3;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == ("select /* test\n"
                             "    continued comments 1\n"
                             "    continued comments 2\n"
                             "    */ 1; -- test comment", False)
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("/* test comment 2\n*/ select 3;", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select  1;", False)
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("select 3;", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_quotes():
    s = """select 'hello', 1; -- test comment
select 23,'hello"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello', 1; -- test comment", False)
        assert next(itr) == ("select 23,'hello", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello', 1;", False)
        assert next(itr) == ("select 23,'hello", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'he"llo', 1; -- test comment
select "23,'hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'he\"llo', 1; -- test comment", False)
        assert next(itr) == ("select \"23,'hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'he\"llo', 1;", False)
        assert next(itr) == ("select \"23,'hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello
', 1; -- test comment
select "23,'hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello\n', 1; -- test comment", False)
        assert next(itr) == ("select \"23,'hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello\n', 1;", False)
        assert next(itr) == ("select \"23,'hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello''
', 1; -- test comment
select "23,'','hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello''\n', 1; -- test comment", False)
        assert next(itr) == ("select \"23,'','hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello''\n', 1;", False)
        assert next(itr) == ("select \"23,'','hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_quotes_in_comments():
    s = """select 'hello'; -- test comment 'hello2' in comment
/* comment 'quote'*/ select true
"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello'; -- test comment 'hello2' in comment", False)
        assert next(itr) == (
            "/* comment 'quote'*/ select true", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_backslash():
    s = """select 'hello\\', 1; -- test comment
select 23,'\nhello"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello\\', 1; -- test comment", False)
        assert next(itr) == ("select 23,'\nhello", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello\\', 1;", False)
        assert next(itr) == ("select 23,'\nhello", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_file_with_slash_star():
    s = """put file:///tmp/* @%tmp;
ls @%tmp;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == ("put file:///tmp/* @%tmp;", True)
        assert next(itr) == ("ls @%tmp;", False)
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("put file:///tmp/* @%tmp;", True)
        assert next(itr) == ("ls @%tmp;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """list @~;
 -- first half
put file://$SELF_DIR/staging-test-data/*.csv.gz @~;
put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;
put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ overwrite=true;
-- second half
put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;
put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;

list @~;
remove @~ pattern='.*.csv.gz';
list @~;
"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == ("list @~;", False)
        # no comment line is returned
        assert next(itr) == (
            "-- first half\n"
            "put file://$SELF_DIR/staging-test-data/*.csv.gz @~;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ "
            "overwrite=true;", True)
        # no comment line is returned
        assert next(itr) == (
            "-- second half\n"
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;", True)
        # no empty line is returned
        assert next(itr) == ("list @~;", False)
        assert next(itr) == ("remove @~ pattern='.*.csv.gz';", False)
        assert next(itr) == ("list @~;", False)
        # last raises StopIteration
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("list @~;", False)
        # no comment line is returned
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/*.csv.gz @~;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ "
            "overwrite=true;", True)
        # no comment line is returned
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;", True)
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;", True)
        # no empty line is returned
        assert next(itr) == ("list @~;", False)
        assert next(itr) == ("remove @~ pattern='.*.csv.gz';", False)
        assert next(itr) == ("list @~;", False)
        # last raises StopIteration
        with pytest.raises(StopIteration):
            next(itr)


def test_sql_with_commands():
    with StringIO(_to_unicode("""create or replace view aaa
    as select * from
    LINEITEM limit 1000;
!spool $outfile
show views like 'AAA';
!spool off
drop view if exists aaa;
show tables""")) as f:
        itr = split_statements(f)
        assert next(itr) == ("""create or replace view aaa
    as select * from
    LINEITEM limit 1000;""", False)

        assert next(itr) == ("""!spool $outfile""", False)
        assert next(itr) == ("show views like 'AAA';", False)
        assert next(itr) == ("!spool off", False)
        assert next(itr) == ("drop view if exists aaa;", False)
        assert next(itr) == ("show tables", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_sql_example1():
    with StringIO(_to_unicode("""
create or replace table a(aa int, bb string);
truncate a;
rm @%a;
put file://a.txt @%a;
copy into a;
select * from a;
drop table if exists a;""")) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "create or replace table a(aa int, bb string);", False)
        assert next(itr) == ("truncate a;", False)
        assert next(itr) == ("rm @%a;", False)
        assert next(itr) == ("put file://a.txt @%a;", True)
        assert next(itr) == ("copy into a;", False)
        assert next(itr) == ("select * from a;", False)
        assert next(itr) == ("drop table if exists a;", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_space_before_put():
    with StringIO(_to_unicode("""
-- sample data uploads
    PUT file:///tmp/data.txt @%ab;
SELECT 1; /* 134 */ select /* 567*/ 345;>
GET @%bcd file:///tmp/aaa.txt;
""")) as f:
        itr = split_statements(f)
        assert next(itr) == ("""-- sample data uploads
    PUT file:///tmp/data.txt @%ab;""", True)
        assert next(itr) == ("""SELECT 1;""", False)
        assert next(itr) == ("""/* 134 */ select /* 567*/ 345;>""", False)
        assert next(itr) == ("""GET @%bcd file:///tmp/aaa.txt;""", True)
        with pytest.raises(StopIteration):
            next(itr)


def test_empty_statement():
    with StringIO(_to_unicode("""select 1;
-- tail comment1
-- tail comment2
""")) as f:
        itr = split_statements(f)
        assert next(itr) == ("""select 1;""", False)
        assert next(itr) == ("""-- tail comment1
-- tail comment2""", None)
        with pytest.raises(StopIteration):
            next(itr)


def test_multiple_comments():
    s = """--- test comment 1
select /*another test comments*/ 1; -- test comment 2
-- test comment 3
select 2;
"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=False)
        assert next(itr) == (
            "--- test comment 1\n"
            "select /*another test comments*/ 1; -- test comment 2", False)
        assert next(itr) == ("-- test comment 3\nselect 2;", False)


def test_comments_with_semicolon():
    s = """--test ;
select 1;
"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=False)
        assert next(itr) == (
            "--test ;\n"
            "select 1;", False
        )
        with pytest.raises(StopIteration):
            next(itr)


def test_comment_in_values():
    """
    SNOW-51297: SnowSQL -o remove_comments=True breaks the query
    """
    # no space before a comment
    s = """INSERT INTO foo
VALUES (/*TIMEOUT*/ 10);"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == (
            "INSERT INTO foo\nVALUES ( 10);", False
        )

    # no space before and after a comment
    s = """INSERT INTO foo
VALUES (/*TIMEOUT*/10);"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == (
            "INSERT INTO foo\nVALUES (10);", False
        )

    # workaround
    s = """INSERT INTO foo
VALUES ( /*TIMEOUT*/ 10);"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == (
            "INSERT INTO foo\nVALUES (  10);", False
        )

    # a comment start from the beginning of the line
    s = """INSERT INTO foo VALUES (
/*TIMEOUT*/
10);"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == (
            "INSERT INTO foo VALUES (\n\n10);", False
        )

def test_multiline_double_dollar_experssion_with_removed_comments():
    s = """CREATE FUNCTION mean(a FLOAT, b FLOAT)
  RETURNS FLOAT LANGUAGE JAVASCRIPT AS $$
  var c = a + b;
  return(c / 2);
  $$;"""
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == (
            "CREATE FUNCTION mean(a FLOAT, b FLOAT)\n"
            "  RETURNS FLOAT LANGUAGE JAVASCRIPT AS $$\n"
            "  var c = a + b;\n  return(c / 2);\n  $$;", False)
