#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import datetime
import random
from typing import Callable

import pytest

try:
    from snowflake.connector.options import installed_pandas
except ImportError:
    installed_pandas = False

try:
    import snowflake.connector.nanoarrow_arrow_iterator  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
@pytest.mark.parametrize("timestamp_type", ("TZ", "LTZ", "NTZ"))
def test_iterate_over_timestamp_chunk(conn_cnx, timestamp_type):
    seed = datetime.datetime.now().timestamp()
    row_numbers = 10
    random.seed(seed)

    # Generate random test data
    def generator_test_data(scale: int) -> Callable[[], int]:
        def generate_test_data() -> int:
            nonlocal scale
            epoch = random.randint(-100_355_968, 2_534_023_007)
            frac = random.randint(0, 10**scale - 1)
            if scale == 8:
                frac *= 10 ** (9 - scale)
                scale = 9
            return int(f"{epoch}{str(frac).rjust(scale, '0')}")

        return generate_test_data

    test_generators = [generator_test_data(i) for i in range(10)]
    test_data = [[g() for g in test_generators] for _ in range(row_numbers)]

    with conn_cnx(
        session_parameters={
            "PYTHON_CONNECTOR_QUERY_RESULT_FORMAT": "ARROW_FORCE",
            "TIMESTAMP_TZ_OUTPUT_FORMAT": "YYYY-MM-DD HH24:MI:SS.FF6 TZHTZM",
            "TIMESTAMP_LTZ_OUTPUT_FORMAT": "YYYY-MM-DD HH24:MI:SS.FF6 TZHTZM",
            "TIMESTAMP_NTZ_OUTPUT_FORMAT": "YYYY-MM-DD HH24:MI:SS.FF6 ",
        }
    ) as conn:
        with conn.cursor() as cur:
            results = cur.execute(
                "select "
                + ", ".join(
                    f"to_timestamp_{timestamp_type}(${s + 1}, {s if s != 8 else 9}) c_{s}"
                    for s in range(10)
                )
                + ", "
                + ", ".join(f"c_{i}::varchar" for i in range(10))
                + f" from values {', '.join(str(tuple(e)) for e in test_data)}"
            ).fetch_arrow_all()
            retrieved_results = [
                list(map(lambda e: e.as_py().strftime("%Y-%m-%d %H:%M:%S.%f %z"), line))
                for line in list(results)[:10]
            ]
            retrieved_strigs = [
                list(map(lambda e: e.as_py().replace("Z", "+0000"), line))
                for line in list(results)[10:]
            ]

            assert retrieved_results == retrieved_strigs
