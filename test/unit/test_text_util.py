import concurrent.futures
import random

import pytest

try:
    from snowflake.connector.util_text import random_string
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
