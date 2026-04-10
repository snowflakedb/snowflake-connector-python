from __future__ import annotations

import types
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

try:
    from snowflake.connector._query_context_cache import QueryContextCache
except ImportError:

    class QueryContextCache:
        def __init__(self, capacity):
            pass


@pytest.mark.parametrize("success", [True, False], ids=["success", "failure"])
async def test_qcc_updated_regardless_of_query_success_async(success):
    """Verify async cmd_query() merges queryContext even when the query fails.

    Regression test for SNOW-3010877: the client must merge queryContext whenever
    the server sends a valid, parseable response, regardless of query status.
    This ensures session consistency for hybrid tables across GS nodes.
    """
    from snowflake.connector.aio._connection import (
        SnowflakeConnection as AsyncSnowflakeConnection,
    )

    # Setup: mock connection with real QCC and real QCC methods (not lambda copies).
    # Only the REST layer is mocked — the full cmd_query -> set_query_context -> QCC
    # chain uses real production code.
    conn = MagicMock()
    conn._disable_query_context_cache = False
    conn.is_query_context_cache_disabled = False
    conn.query_context_cache = QueryContextCache(5)
    conn.query_context_cache_size = 5

    # Bind the REAL get/set_query_context methods (inherited from sync class).
    conn.get_query_context = types.MethodType(
        AsyncSnowflakeConnection.get_query_context, conn
    )
    conn.set_query_context = types.MethodType(
        AsyncSnowflakeConnection.set_query_context, conn
    )

    # Pre-populate QCC with an initial entry
    conn.query_context_cache.insert(1, 100, 1, "initial")
    conn.query_context_cache._sync_priority_map()
    assert len(conn.query_context_cache) == 1

    # Mock server response — includes queryContext regardless of success/failure
    expected_code = "0" if success else "1234"
    expected_message = "" if success else "Query failed"
    new_qc_entry = {"id": 2, "timestamp": 200, "priority": 2, "context": "from_server"}
    conn.rest.request = AsyncMock(
        return_value={
            "success": success,
            "code": expected_code,
            "message": expected_message,
            "data": {
                "queryId": "test-query-id",
                "queryContext": {"entries": [new_qc_entry]},
            },
        }
    )

    # Act: call async cmd_query directly (unbound method on mock self)
    ret = await AsyncSnowflakeConnection.cmd_query(conn, "SELECT 1", 1, uuid.uuid4())

    # Assert: every assertion runs unconditionally for every parametrization
    assert ret["success"] == success
    assert ret["code"] == expected_code, "Response code must be preserved"
    assert ret["message"] == expected_message, "Response message must be preserved"
    assert (
        len(conn.query_context_cache) == 2
    ), f"QCC should contain 2 entries (initial + from_server) when success={success}"
    entry_ids = {e.id for e in conn.query_context_cache._get_elements()}
    assert 1 in entry_ids, "Original entry should still be present"
    assert 2 in entry_ids, "New entry from server response should have been merged"
