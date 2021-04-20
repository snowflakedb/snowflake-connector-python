#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from io import StringIO

import pytest

from snowflake.connector.util_text import split_statements

try:
    from snowflake.connector.util_text import SQLDelimiter
except ImportError:
    SQLDelimiter = None


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_simple_sql():
    with StringIO("show tables") as f:
        itr = split_statements(f)
        assert next(itr) == ("show tables", False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO("show tables;") as f:
        itr = split_statements(f)
        assert next(itr) == ("show tables;", False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO("select 1;select 2") as f:
        itr = split_statements(f)
        assert next(itr) == ("select 1;", False)
        assert next(itr) == ("select 2", False)
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO("select 1;select 2;") as f:
        itr = split_statements(f)
        assert next(itr) == ("select 1;", False)
        assert next(itr) == ("select 2;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = "select 1; -- test"
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 1;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = "select /* test */ 1; -- test comment select 1;"
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select /* test */ 1;", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_multiple_line_sql():
    s = "select /* test */ 1; -- test comment\nselect 23;"

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == (("select /* test */ 1;", False))
        assert next(itr) == ("select 23;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; -- test comment 2"""

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select /* test */ 1;", False)
        assert next(itr) == ("select 23;", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2 */ select 3"""

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select /* test */ 1;", False)
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("select 3", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2
*/ select 3;"""

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select /* test */ 1;", False)
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

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select /* test\n"
            "    continued comments 1\n"
            "    continued comments 2\n"
            "    */ 1;",
            False,
        )
        assert next(itr) == ("select 23;", False)
        assert next(itr) == ("select 3;", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_quotes():
    s = "select 'hello', 1; -- test comment\nselect 23,'hello"

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 'hello', 1;", False)
        assert next(itr) == ("select 23,'hello", False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'he"llo', 1; -- test comment
select "23,'hello" """

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 'he\"llo', 1;", False)
        assert next(itr) == ('select "23,\'hello"', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello
', 1; -- test comment
select "23,'hello" """

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 'hello\n', 1;", False)
        assert next(itr) == ('select "23,\'hello"', False)
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello''
', 1; -- test comment
select "23,'','hello" """

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 'hello''\n', 1;", False)
        assert next(itr) == ("select \"23,'','hello\"", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_quotes_in_comments():
    s = "select 'hello'; -- test comment 'hello2' in comment\n/* comment 'quote'*/ select true\n"
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello';",
            False,
        )
        assert next(itr) == ("select true", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_backslash():
    """Tests backslash in a literal.

    Notes:
        The backslash is escaped in a Python string literal. Double backslashes in a string literal represents a
        single backslash.
    """
    s = "select 'hello\\\\', 1; -- test comment\nselect 23,'\nhello"

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 'hello\\\\', 1;", False)
        assert next(itr) == ("select 23,'\nhello", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_file_with_slash_star():
    s = "put file:///tmp/* @%tmp;\nls @%tmp;"

    with StringIO(s) as f:
        itr = split_statements(f)
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

    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("list @~;", False)
        # no comment line is returned
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/*.csv.gz @~;",
            True,
        )
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;",
            True,
        )
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ " "overwrite=true;",
            True,
        )
        # no comment line is returned
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;",
            True,
        )
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;",
            True,
        )
        # no empty line is returned
        assert next(itr) == ("list @~;", False)
        assert next(itr) == ("remove @~ pattern='.*.csv.gz';", False)
        assert next(itr) == ("list @~;", False)
        # last raises StopIteration
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_sql_with_commands():
    with StringIO(
        """create or replace view aaa
    as select * from
    LINEITEM limit 1000;
!spool $outfile
show views like 'AAA';
!spool off
drop view if exists aaa;
show tables"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == (
            """create or replace view aaa
    as select * from
    LINEITEM limit 1000;""",
            False,
        )

        assert next(itr) == ("""!spool $outfile""", False)
        assert next(itr) == ("show views like 'AAA';", False)
        assert next(itr) == ("!spool off", False)
        assert next(itr) == ("drop view if exists aaa;", False)
        assert next(itr) == ("show tables", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_sql_example1():
    with StringIO(
        """
create or replace table a(aa int, bb string);
truncate a;
rm @%a;
put file://a.txt @%a;
copy into a;
select * from a;
drop table if exists a;"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == ("create or replace table a(aa int, bb string);", False)
        assert next(itr) == ("truncate a;", False)
        assert next(itr) == ("rm @%a;", False)
        assert next(itr) == ("put file://a.txt @%a;", True)
        assert next(itr) == ("copy into a;", False)
        assert next(itr) == ("select * from a;", False)
        assert next(itr) == ("drop table if exists a;", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_space_before_put():
    with StringIO(
        """
-- sample data uploads
    PUT file:///tmp/data.txt @%ab;
SELECT 1; /* 134 */ select /* 567*/ 345;
GET @%bcd file:///tmp/aaa.txt;
"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == (
            """PUT file:///tmp/data.txt @%ab;""",
            True,
        )
        assert next(itr) == ("""SELECT 1;""", False)
        assert next(itr) == ("""select /* 567*/ 345;""", False)
        assert next(itr) == ("""GET @%bcd file:///tmp/aaa.txt;""", True)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_empty_statement():
    with StringIO(
        """select 1;
-- tail comment1
-- tail comment2
"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == ("""select 1;""", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_multiple_comments():
    s = """--- test comment 1
select /*another test comments*/ 1; -- test comment 2
-- test comment 3
select 2;
"""
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select /*another test comments*/ 1;",
            False,
        )
        assert next(itr) == ("select 2;", False)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_comments_with_semicolon():
    s = """--test ;
select 1;
"""
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("select 1;", False)
        with pytest.raises(StopIteration):
            next(itr)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_backslash_quote_escape():
    s = """
SELECT 1 'Snowflake\\'s 1';
SELECT 2 'Snowflake\\'s 2'
"""
    with StringIO(s) as f:
        itr = split_statements(f)
        assert next(itr) == ("SELECT 1 'Snowflake\\'s 1';", False)
        assert next(itr) == ("SELECT 2 'Snowflake\\'s 2'", False)


@pytest.mark.skipif(split_statements is None, reason="No split_statements is available")
def test_sql_delimiter():
    """Copy of test_sql_with_commands but with an unconventional sql_delimiter.

    This test should not only verify that a random delimiter splits SQL commands correctly, but
    also that semi colon gets added for the split statements instead of the reserved custom keywords.

    Since this is a generator function the sql_delimiter cannot be passed in as a string as it might change
    during execution, so the SnowSQL's cli class is passed in by SnowSQL. This function makes sure that this
    behaviour is not broken by mistake.
    """
    delimiter = ";"
    with StringIO(
        (
            "create or replace view aaa\n"
            "        as select * from\n"
            "        LINEITEM limit 1000 {delimiter}\n"
            "!spool $outfile\n"
            "show views like 'AAA'{delimiter}\n"
            "!spool off\n"
            "drop view if exists aaa {delimiter}\n"
            "show tables"
        ).format(delimiter=delimiter)
    ) as f:
        itr = split_statements(f)
        assert next(itr) == (
            """create or replace view aaa
        as select * from
        LINEITEM limit 1000 ;""",
            False,
        )

        assert next(itr) == ("""!spool $outfile""", False)
        assert next(itr) == ("show views like 'AAA';", False)
        assert next(itr) == ("!spool off", False)
        assert next(itr) == ("drop view if exists aaa ;", False)
        assert next(itr) == ("show tables", False)
    with pytest.raises(StopIteration):
        next(itr)


# In new approach, we are not using SQLDelimiter so this test is always skipped
@pytest.mark.skipif(
    split_statements is None or SQLDelimiter is None,
    reason="No split_statements or SQLDelimiter is available",
)
@pytest.mark.parametrize(
    "sql, delimiter, split_stmnts",
    [
        ("select 1 as a__b __ select 1", "__", ["select 1 as a__b ;", "select 1"]),
        ("select 1 as a__b/", "/", ["select 1 as a__b;"]),
        ('select 1 as "ab" ab', "ab", ['select 1 as "ab" ;']),
        ('select 1 as "ab"ab', "ab", ['select 1 as "ab";']),
        ("select 1 as abab", "ab", ["select 1 as abab"]),
        ("insert into table t1 values (1)/", "/", ["insert into table t1 values (1);"]),
        ("select 1 as a$_", "_", ["select 1 as a$_"]),
        ("select 1 as _$", "_", ["select 1 as _$"]),
    ],
)
def test_sql_splitting_various(sql, delimiter, split_stmnts):
    """This tests various smaller sql splitting pitfalls."""
    with StringIO(sql) as sqlio:
        statements = list(
            [s[0] for s in split_statements(sqlio, delimiter=SQLDelimiter(delimiter))]
        )
    assert statements == split_stmnts


def test_sql_createproc_js():
    with StringIO(
        """
    CREATE ROW ACCESS POLICY nullary_policy AS () RETURNS BOOLEAN -> true;
    create or replace procedure stproc1(FLOAT_PARAM1 FLOAT)
    returns string
    language javascript
    strict
    execute as owner
    as
    $$
    var sql_command =
     "INSERT INTO stproc_test_table1 (num_col1) VALUES (" + FLOAT_PARAM1 + ")";
    try {
        snowflake.execute (
            {sqlText: sql_command}
            );
        return "Succeeded.";   // Return a success/error indicator.
        }
    catch (err)  {
        return "Failed: " + err;   // Return a success/error indicator.
        }
    $$
    begin
    /* test comment 3 */
    NULL;
    RETURN 3;
    end;

    """
    ) as f:
        itr = split_statements(f)
        assert next(itr) == (
            """CREATE ROW ACCESS POLICY nullary_policy AS () RETURNS BOOLEAN -> true;""",
            False,
        )
        assert next(itr) == (
            """create or replace procedure stproc1(FLOAT_PARAM1 FLOAT)
    returns string
    language javascript
    strict
    execute as owner
    as
    $$
    var sql_command =
     "INSERT INTO stproc_test_table1 (num_col1) VALUES (" + FLOAT_PARAM1 + ")";
    try {
        snowflake.execute (
            {sqlText: sql_command}
            );
        return "Succeeded.";   // Return a success/error indicator.
        }
    catch (err)  {
        return "Failed: " + err;   // Return a success/error indicator.
        }
    $$""",
            False,
        )
        assert next(itr) == (
            """begin
    /* test comment 3 */
    NULL;
    RETURN 3;
    end;""",
            False,
        )
        with pytest.raises(StopIteration):
            next(itr)


def test_sql_createproc_sql():
    with StringIO(
        """
    CREATE TABLE T(a INTERVAL DAY(5));
    select a from b;
    create or replace procedure create_tables() as
    begin
    create table emp_us (deptno number, name variant);
    create table emp_uk (deptno number, name variant);
    end;
    call create_tables();
    put file:///a.txt @stage1;
    """
    ) as f:
        itr = split_statements(f)
        assert next(itr) == ("CREATE TABLE T(a INTERVAL DAY(5));", False)
        assert next(itr) == ("select a from b;", False)
        assert next(itr) == (
            """create or replace procedure create_tables() as
    begin
    create table emp_us (deptno number, name variant);
    create table emp_uk (deptno number, name variant);
    end;""",
            False,
        )
        assert next(itr) == ("call create_tables();", False)
        assert next(itr) == ("put file:///a.txt @stage1;", True)
        with pytest.raises(StopIteration):
            next(itr)


def test_sql_nested_anonymous_block():
    with StringIO(
        """            select a from b where c=3;
            DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;
            put a to @b;
begin transaction;
insert into table1 (i) values (1);
insert into table1 (i) values ('This is not a valid integer.');    -- FAILS!
insert into table1 (i) values (2);
commit;
select case collate('m', 'upper')
    when 'M' then true
    else false
end;
            begin;
insert into table2 ...;
commit;

"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == ("""select a from b where c=3;""", False)
        assert next(itr) == (
            """DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;""",
            False,
        )
        assert next(itr) == ("""put a to @b;""", True)
        assert next(itr) == ("""begin transaction;""", False)
        assert next(itr) == ("""insert into table1 (i) values (1);""", False)
        assert next(itr) == (
            """insert into table1 (i) values ('This is not a valid integer.');""",
            False,
        )
        assert next(itr) == ("""insert into table1 (i) values (2);""", False)
        assert next(itr) == ("""commit;""", False)
        assert next(itr) == (
            """select case collate('m', 'upper')
    when 'M' then true
    else false
end;""",
            False,
        )
        assert next(itr) == ("""begin;""", False)
        assert next(itr) == ("""insert into table2 ...;""", False)
        assert next(itr) == ("""commit;""", False)
        with pytest.raises(StopIteration):
            next(itr)


def test_sql_creatproc_declare_stmt():
    with StringIO(
        """    select a from b;
    create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;
            GET file:///a.txt @stage1;"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == ("select a from b;", False)
        assert next(itr) == (
            """create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;""",
            False,
        )
        assert next(itr) == ("""GET file:///a.txt @stage1;""", True)
        with pytest.raises(StopIteration):
            next(itr)


def test_auto_off():
    with StringIO(
        """
        --SF:auto_split off
        insert into table1 (i) values ('This is not a valid integer.');
        select a from b;
        --SF:<<
    create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;
            --SF:>>
            GET file:///a.txt @stage1;"""
    ) as f:
        itr = split_statements(f)
        stmt = next(itr)
        print(stmt[0])
        assert stmt == (
            """--SF:auto_split off
        insert into table1 (i) values ('This is not a valid integer.');
        select a from b;""",
            False,
        )
        stmt = next(itr)
        print(stmt)
        assert stmt == (
            """create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
              Y NUMBER DEFAULT X;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X+Y;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;""",
            False,
        )
        stmt = next(itr)
        print(stmt)
        assert stmt == ("GET file:///a.txt @stage1;", True)
        with pytest.raises(StopIteration):
            next(itr)


def test_auto_with_comments():
    with StringIO(
        """
        insert into table1 (i) values ('This is not a valid integer.');
        --SF:<<>>
        select a from b;
        --SF:<<
        insert into table1 (i) values ('!@#$%^&*()?<>--<<>>');
    create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;
            --SF:>>
            GET file:///a.txt @stage1;"""
    ) as f:
        itr = split_statements(f)
        assert next(itr) == (
            """insert into table1 (i) values ('This is not a valid integer.');""",
            False,
        )
        assert next(itr) == ("""select a from b;""", False)
        assert next(itr) == (
            """insert into table1 (i) values ('!@#$%^&*()?<>--<<>>');
    create or replace procedure create_tables() as             DECLARE
              X NUMBER DEFAULT 0;
            BEGIN
              DECLARE
                Z NUMBER DEFAULT X;
              BEGIN
                SET X := 5;
                RETURN Z;
              END;
            END;""",
            False,
        )
        assert next(itr) == ("GET file:///a.txt @stage1;", True)
        with pytest.raises(StopIteration):
            next(itr)
