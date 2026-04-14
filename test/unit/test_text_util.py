import concurrent.futures
import random

import pytest

try:
    from snowflake.connector.util_text import extract_values_clause, random_string
except ImportError:
    pass

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module


def test_random_string_generation_with_same_global_seed():
    random.seed(42)
    random_string1 = random_string()
    random.seed(42)
    random_string2 = random_string()
    assert (
        isinstance(random_string1, str)
        and isinstance(random_string2, str)
        and random_string1 != random_string2
    )

    def get_random_string():
        random.seed(42)
        return random_string()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Submit tasks to the pool and get future objects
        futures = [executor.submit(get_random_string) for _ in range(5)]
        res = [f.result() for f in futures]
        assert len(set(res)) == 5  # no duplicate string


# ---------------------------------------------------------------------------
# extract_values_clause tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql, expected",
    [
        # Simple pyformat single column
        (
            "INSERT INTO t (col) VALUES (%(col)s)",
            "(%(col)s)",
        ),
        # printf-style %s / %d
        (
            "INSERT INTO t (a, b) VALUES (%s, %d)",
            "(%s, %d)",
        ),
        # Nested function call — the bug case for @compiles VARIANT (PARSE_JSON)
        (
            "INSERT INTO t (col) VALUES (PARSE_JSON(%(col)s))",
            "(PARSE_JSON(%(col)s))",
        ),
        # VARIANT cast via :: — another common @compiles pattern
        (
            "INSERT INTO t (col) VALUES (%(col)s::VARIANT)",
            "(%(col)s::VARIANT)",
        ),
        # PARSE_JSON + VARIANT cast combined
        (
            "INSERT INTO t (col) VALUES (PARSE_JSON(%(col)s)::VARIANT)",
            "(PARSE_JSON(%(col)s)::VARIANT)",
        ),
        # Multiple columns, one with nested function
        (
            "INSERT INTO t (a, b) VALUES (%(a)s, PARSE_JSON(%(b)s))",
            "(%(a)s, PARSE_JSON(%(b)s))",
        ),
        # String literal with parens inside — must not confuse depth counter
        (
            "INSERT INTO t (col) VALUES (%s, '))((' )()",
            "(%s, '))((' )",
        ),
        # Subquery form that used to return an extra ')' with the greedy regex
        # (SNOW-298756 / PR #657 bug case)
        (
            'INSERT INTO "MESSAGES" (raw) (SELECT PARSE_JSON(column1) as raw from values (%(raw)s))',
            "(%(raw)s)",
        ),
        # VALUES keyword is case-insensitive
        (
            "INSERT INTO t (col) values (%(col)s)",
            "(%(col)s)",
        ),
        # No VALUES clause → None
        (
            "INSERT INTO t SELECT col FROM src",
            None,
        ),
        # Dollar-quoted string containing parens — depth must not be affected
        (
            "INSERT INTO t (col) VALUES ($$)$$)",
            "($$)$$)",
        ),
    ],
)
def test_extract_values_clause(sql, expected):
    assert extract_values_clause(sql) == expected
