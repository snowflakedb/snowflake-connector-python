from io import StringIO

import pytest

from snowflake.connector.compat import PY2
from snowflake.connector.util_text import split_statements


def _to_unicode(sql):
    return sql.decode('utf-8') if PY2 and isinstance(sql, str) else sql


def test_simple_sql():
    with StringIO(_to_unicode("show tables")) as f:
        itr = split_statements(f)
        assert next(itr) == 'show tables'
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("show tables;")) as f:
        itr = split_statements(f)
        assert next(itr) == 'show tables;'
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("select 1;select 2")) as f:
        itr = split_statements(f)
        assert next(itr) == 'select 1;'
        assert next(itr) == 'select 2'
        with pytest.raises(StopIteration):
            next(itr)

    with StringIO(_to_unicode("select 1;select 2;")) as f:
        itr = split_statements(f)
        assert next(itr) == 'select 1;'
        assert next(itr) == 'select 2;'
        with pytest.raises(StopIteration):
            next(itr)

    s = "select 1; -- test"
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == 'select 1; -- test'
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == 'select 1;'
        with pytest.raises(StopIteration):
            next(itr)

    s = "select /* test */ 1; -- test comment select 1;"
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment select 1;')
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;')
        with pytest.raises(StopIteration):
            next(itr)


def test_multiple_line_sql():
    s = """select /* test */ 1; -- test comment
select 23;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment')
        assert next(itr) == 'select 23;'
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;')
        assert next(itr) == 'select 23;'
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; -- test comment 2"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment')
        assert next(itr) == 'select 23; -- test comment 2'
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;')
        assert next(itr) == 'select 23;'
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2 */ select 3"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            'select /* test */ 1; -- test comment')
        assert next(itr) == 'select 23;'
        assert next(itr) == '/* test comment 2 */ select 3'
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ('select  1;')
        assert next(itr) == 'select 23;'
        assert next(itr) == 'select 3'
        with pytest.raises(StopIteration):
            next(itr)

    s = """select /* test */ 1; -- test comment
select 23; /* test comment 2
*/ select 3;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select /* test */ 1; -- test comment")
        assert next(itr) == "select 23;"
        assert next(itr) == "/* test comment 2\n*/ select 3;"
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == "select  1;"
        assert next(itr) == "select 23;"
        assert next(itr) == "select 3;"
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
        assert next(itr) == (("select /* test\n"
                              "    continued comments 1\n"
                              "    continued comments 2\n"
                              "    */ 1; -- test comment"))
        assert next(itr) == "select 23;"
        assert next(itr) == "/* test comment 2\n*/ select 3;"
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == "select  1;"
        assert next(itr) == "select 23;"
        assert next(itr) == "select 3;"
        with pytest.raises(StopIteration):
            next(itr)


def test_quotes():
    s = """select 'hello', 1; -- test comment
select 23,'hello"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello', 1; -- test comment")
        assert next(itr) == "select 23,'hello"
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello', 1;")
        assert next(itr) == "select 23,'hello"
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'he"llo', 1; -- test comment
select "23,'hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'he\"llo', 1; -- test comment")
        assert next(itr) == "select \"23,'hello\""
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'he\"llo', 1;")
        assert next(itr) == "select \"23,'hello\""
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello
', 1; -- test comment
select "23,'hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello\n', 1; -- test comment")
        assert next(itr) == "select \"23,'hello\""
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello\n', 1;")
        assert next(itr) == "select \"23,'hello\""
        with pytest.raises(StopIteration):
            next(itr)

    s = """select 'hello''
', 1; -- test comment
select "23,'','hello" """

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello''\n', 1; -- test comment")
        assert next(itr) == "select \"23,'','hello\""
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello''\n', 1;")
        assert next(itr) == "select \"23,'','hello\""
        with pytest.raises(StopIteration):
            next(itr)


def test_backslash():
    s = """select 'hello\\', 1; -- test comment
select 23,'\nhello"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == (
            "select 'hello\\', 1; -- test comment")
        assert next(itr) == "select 23,'\nhello"
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == ("select 'hello\\', 1;")
        assert next(itr) == "select 23,'\nhello"
        with pytest.raises(StopIteration):
            next(itr)


def test_file_with_slash_star():
    s = """put file:///tmp/* @%tmp;
ls @%tmp;"""

    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f)
        assert next(itr) == """put file:///tmp/* @%tmp;"""
        assert next(itr) == "ls @%tmp;"
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == """put file:///tmp/* @%tmp;"""
        assert next(itr) == "ls @%tmp;"
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
        assert next(itr) == "list @~;"
        # no comment line is returned
        assert next(itr) == (
            ("-- first half\n"
             "put file://$SELF_DIR/staging-test-data/*.csv.gz @~;"))
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;")
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ "
            "overwrite=true;")
        # no comment line is returned
        assert next(itr) == (
            ("-- second half\n"
             "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;"))
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;")
        # no empty line is returned
        assert next(itr) == "list @~;"
        assert next(itr) == "remove @~ pattern='.*.csv.gz';"
        assert next(itr) == "list @~;"
        # last raises StopIteration
        with pytest.raises(StopIteration):
            next(itr)
    with StringIO(_to_unicode(s)) as f:
        itr = split_statements(f, remove_comments=True)
        assert next(itr) == "list @~;"
        # no comment line is returned
        assert next(itr) == (
            ("put file://$SELF_DIR/staging-test-data/*.csv.gz @~;"))
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~;")
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/foo.csv.gz @~ "
            "overwrite=true;")
        # no comment line is returned
        assert next(itr) == (
            ("put file://$SELF_DIR/staging-test-data/foo.csv.gz @~/foo;"))
        assert next(itr) == (
            "put file://$SELF_DIR/staging-test-data/bar.csv.gz @~/bar;")
        # no empty line is returned
        assert next(itr) == "list @~;"
        assert next(itr) == "remove @~ pattern='.*.csv.gz';"
        assert next(itr) == "list @~;"
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
        assert next(itr) == """create or replace view aaa
    as select * from
    LINEITEM limit 1000;"""

        assert next(itr) == """!spool $outfile"""
        assert next(itr) == "show views like 'AAA';"
        assert next(itr) == "!spool off"
        assert next(itr) == "drop view if exists aaa;"
        assert next(itr) == "show tables"
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
            "create or replace table a(aa int, bb string);")
        assert next(itr) == "truncate a;"
        assert next(itr) == "rm @%a;"
        assert next(itr) == "put file://a.txt @%a;"
        assert next(itr) == "copy into a;"
        assert next(itr) == "select * from a;"
        assert next(itr) == "drop table if exists a;"
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
            "select /*another test comments*/ 1; -- test comment 2")
        assert next(itr) == ("-- test comment 3\nselect 2;")
