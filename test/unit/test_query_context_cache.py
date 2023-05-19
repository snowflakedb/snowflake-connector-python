#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import json
from random import shuffle

import pytest

try:
    from snowflake.connector._query_context_cache import (
        QueryContextCache,
        QueryContextElement,
    )
except ImportError:

    class QueryContextCache:
        def __init__(self, capacity):
            pass

    class QueryContextElement:
        def __init__(self, id, read_timestamp, priority, context):
            pass


MAX_CAPACITY = 5
BASE_ID = 0
BASE_READ_TIMESTAMP = 1668727958
BASE_PRIORITY = 0
CONTEXT = "////Some query context"


class ExpectedQCCData:
    def __init__(self, capacity, context=CONTEXT) -> None:
        self.capacity = capacity
        self.ids = [BASE_ID + i for i in range(capacity)]
        self.timestamps = [BASE_READ_TIMESTAMP + i for i in range(capacity)]
        self.priorities = [BASE_PRIORITY + i for i in range(capacity)]
        self.contexts = [context for _ in range(capacity)]

    def shuffle_data(self) -> None:
        random_order = list(range(self.capacity))
        shuffle(random_order)
        self.ids = [BASE_ID + i for i in random_order]
        self.timestamps = [BASE_READ_TIMESTAMP + i for i in random_order]
        self.priorities = [BASE_PRIORITY + i for i in random_order]

    def reset_data(self):
        self.ids = [BASE_ID + i for i in range(self.capacity)]
        self.timestamps = [BASE_READ_TIMESTAMP + i for i in range(self.capacity)]
        self.priorities = [BASE_PRIORITY + i for i in range(self.capacity)]


@pytest.fixture()
def expected_data() -> ExpectedQCCData:
    data = ExpectedQCCData(MAX_CAPACITY)
    yield data
    data.reset_data()


@pytest.fixture()
def expected_data_with_null_context() -> ExpectedQCCData:
    data = ExpectedQCCData(MAX_CAPACITY, context=None)
    yield data
    data.reset_data()


@pytest.fixture()
def qcc_with_no_data() -> QueryContextCache:
    return QueryContextCache(MAX_CAPACITY)


@pytest.fixture()
def qcc_with_data(
    qcc_with_no_data: QueryContextCache, expected_data: ExpectedQCCData
) -> QueryContextCache:
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.insert(
            expected_data.ids[i],
            expected_data.timestamps[i],
            expected_data.priorities[i],
            expected_data.contexts[i],
        )
    qcc_with_no_data._sync_priority_map()
    yield qcc_with_no_data
    qcc_with_no_data.clear_cache()


@pytest.fixture()
def qcc_with_data_random_order(
    qcc_with_no_data: QueryContextCache,
    expected_data: ExpectedQCCData,
) -> QueryContextCache:
    expected_data.shuffle_data()
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.insert(
            expected_data.ids[i],
            expected_data.timestamps[i],
            expected_data.priorities[i],
            expected_data.contexts[i],
        )
    qcc_with_no_data._sync_priority_map()
    yield qcc_with_no_data
    qcc_with_no_data.clear_cache()


@pytest.fixture()
def qcc_with_data_null_context(
    qcc_with_no_data: QueryContextCache,
    expected_data_with_null_context: ExpectedQCCData,
):
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.insert(
            expected_data_with_null_context.ids[i],
            expected_data_with_null_context.timestamps[i],
            expected_data_with_null_context.priorities[i],
            expected_data_with_null_context.contexts[i],
        )
    qcc_with_no_data._sync_priority_map()
    yield qcc_with_no_data
    qcc_with_no_data.clear_cache()


def assert_cache_with_data(
    qcc: QueryContextCache, expected_data: ExpectedQCCData
) -> None:
    assert len(qcc) == MAX_CAPACITY

    for idx, qce in enumerate(qcc._get_elements()):
        assert expected_data.ids[idx] == qce.id
        assert expected_data.timestamps[idx] == qce.read_timestamp
        assert expected_data.priorities[idx] == qce.priority
        assert expected_data.contexts[idx] == qce.context


def test_is_empty(qcc_with_no_data: QueryContextCache):
    assert len(qcc_with_no_data) == 0


def test_deserialize_type_error():
    json_string = """{ "entries": null }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 0  # because of TypeError, the qcc is cleared

    json_string = """{
        "entries":[
            {
            "id": "abc",
            "read_timestamp": 1629456000,
            "priority": 0,
            "context": "sample_base64_encoded_context"
            }
        ]
    }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)  # convert JSON to dict
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 0  # because of TypeError, the qcc is cleared

    json_string = """{
        "entries":[
            {
            "id": 0,
            "timestamp": 111.111,
            "priority": 0,
            "context": "sample_base64_encoded_context"
            }
        ]
    }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)  # convert JSON to dict
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 0  # because of TypeError, the qcc is cleared

    json_string = """{
        "entries":[
            {
            "id": 0,
            "timestamp": 123412123,
            "priority": "main",
            "context": "sample_base64_encoded_context"
            }
        ]
    }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)  # convert JSON to dict
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 0  # because of TypeError, the qcc is cleared

    json_string = """{
        "entries":[
            {
            "id": 0,
            "timestamp": 1112314121,
            "priority": 0,
            "context": 1231412
            }
        ]
    }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)  # convert JSON to dict
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 0  # because of TypeError, the qcc is cleared

    json_string = """{
        "entries":[
            {
            "id": 0,
            "timestamp": 123142341,
            "priority": 0,
            "context": "sample_base64_encoded_context"
            }
        ]
    }"""
    qcc = QueryContextCache(MAX_CAPACITY)
    data = json.loads(json_string)  # convert JSON to dict
    qcc.deserialize_json_dict(data)
    assert len(qcc) == 1  # because this time the input is correct, qcc size should be 1


def test_with_data(qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData):
    assert_cache_with_data(qcc_with_data, expected_data)


def test_with_data_in_random_order(
    qcc_with_data_random_order: QueryContextCache, expected_data: ExpectedQCCData
):
    expected_data.reset_data()
    assert_cache_with_data(qcc_with_data_random_order, expected_data)


def test_trim_cache(qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData):
    qcc_with_data.insert(
        BASE_ID + MAX_CAPACITY,
        BASE_READ_TIMESTAMP + MAX_CAPACITY,
        BASE_PRIORITY + MAX_CAPACITY,
        CONTEXT,
    )
    qcc_with_data._sync_priority_map()
    qcc_with_data.trim_cache()

    assert_cache_with_data(qcc_with_data, expected_data)


def test_update_timestamp(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    update_id = 1
    qcc_with_data.insert(
        BASE_ID + update_id,
        BASE_READ_TIMESTAMP + update_id + 10,
        BASE_PRIORITY + update_id,
        CONTEXT,
    )
    qcc_with_data._sync_priority_map()
    expected_data.timestamps[update_id] = BASE_READ_TIMESTAMP + update_id + 10
    assert_cache_with_data(qcc_with_data, expected_data)


def test_update_priority(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    update_id = 3
    updated_priority = BASE_PRIORITY + update_id + 7
    qcc_with_data.insert(
        BASE_ID + update_id, BASE_READ_TIMESTAMP + update_id, updated_priority, CONTEXT
    )
    qcc_with_data._sync_priority_map()

    for i in range(update_id, MAX_CAPACITY - 1):
        expected_data.ids[i] = expected_data.ids[i + 1]
        expected_data.timestamps[i] = expected_data.timestamps[i + 1]
        expected_data.priorities[i] = expected_data.priorities[i + 1]
    expected_data.ids[MAX_CAPACITY - 1] = BASE_ID + update_id
    expected_data.timestamps[MAX_CAPACITY - 1] = BASE_READ_TIMESTAMP + update_id
    expected_data.priorities[MAX_CAPACITY - 1] = updated_priority

    assert_cache_with_data(qcc_with_data, expected_data)


def test_add_same_priority(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    i = MAX_CAPACITY
    updated_priority = BASE_PRIORITY + 1
    qcc_with_data.insert(
        BASE_ID + i, BASE_READ_TIMESTAMP + i, updated_priority, CONTEXT
    )
    qcc_with_data._sync_priority_map()

    expected_data.ids[1] = BASE_ID + i
    expected_data.timestamps[1] = BASE_READ_TIMESTAMP + i
    assert_cache_with_data(qcc_with_data, expected_data)


# helper function to shuffle priorities in all entries
def random_priority_shuffle(num_entries: int):
    id_list = list(range(BASE_ID, BASE_ID + num_entries))
    priority_list = list(range(BASE_PRIORITY, BASE_PRIORITY + num_entries))
    # Shuffle priorities randomly
    shuffle(priority_list)

    # Create a dictionary mapping IDs to their new random priorities
    id_to_priority = dict(zip(id_list, priority_list))
    return id_to_priority


def test_priority_switch_randomized(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    num_retry = MAX_CAPACITY * 5
    for _ in range(num_retry):
        # for each iteration, we simulate randomized priority switch for the batch of QCEs.
        id_to_priority = random_priority_shuffle(MAX_CAPACITY)

        # Update priorities using the random shuffle
        for id, priority in id_to_priority.items():
            qcc_with_data.insert(
                id, BASE_READ_TIMESTAMP + MAX_CAPACITY + 10, priority, CONTEXT
            )

        qcc_with_data._sync_priority_map()

        # Check if the inner priority map has been correctly updated
        for id, priority in id_to_priority.items():
            assert qcc_with_data._priority_map[priority].id == id
        # Check if the inner id map has been correctly updated
        for id in range(MAX_CAPACITY):
            assert qcc_with_data._id_map[id].id == id
        # Update expected_data
        for idx, id in enumerate(
            sorted(id_to_priority.keys(), key=lambda x: id_to_priority[x])
        ):
            expected_data.ids[idx] = id
            expected_data.timestamps[idx] = BASE_READ_TIMESTAMP + MAX_CAPACITY + 10

        assert_cache_with_data(qcc_with_data, expected_data)


def test_same_id_with_stale_timestamp(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    i = 2
    qcc_with_data.insert(
        BASE_ID + i, BASE_READ_TIMESTAMP + i - 10, BASE_PRIORITY + i, CONTEXT
    )
    qcc_with_data._sync_priority_map()
    qcc_with_data.trim_cache()

    assert_cache_with_data(qcc_with_data, expected_data)


def test_empty_cache_with_null_data(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)

    qcc_with_data.deserialize_json_dict(None)
    assert len(qcc_with_data) == 0


def test_empty_cache_with_empty_response_data(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)

    qcc_with_data.deserialize_json_dict("")
    assert len(qcc_with_data) == 0


def test_serialization_deserialization_with_null_context(
    qcc_with_data_null_context: QueryContextCache,
    expected_data_with_null_context: ExpectedQCCData,
):
    assert_cache_with_data(qcc_with_data_null_context, expected_data_with_null_context)

    data = qcc_with_data_null_context.serialize_to_json()
    qcc_with_data_null_context.clear_cache()
    assert len(qcc_with_data_null_context) == 0

    data = json.loads(data)  # convert JSON to dict
    qcc_with_data_null_context.deserialize_json_dict(data)
    assert_cache_with_data(qcc_with_data_null_context, expected_data_with_null_context)


def test_serialization_deserialization(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)

    data = qcc_with_data.serialize_to_json()
    qcc_with_data.clear_cache()
    assert len(qcc_with_data) == 0

    data = json.loads(data)  # convert JSON to dict
    qcc_with_data.deserialize_json_dict(data)
    assert_cache_with_data(qcc_with_data, expected_data)


def test_eviction_order():
    qce1 = QueryContextElement(id=1, read_timestamp=13323, priority=1, context=None)
    qce2 = QueryContextElement(id=2, read_timestamp=15522, priority=4, context="")

    qce3 = QueryContextElement(
        id=3, read_timestamp=8383, priority=99, context="generic context"
    )

    qce_list = [qce1, qce2, qce3]
    qcc = QueryContextCache(5)
    for qce in qce_list:
        qcc.insert(qce.id, qce.read_timestamp, qce.priority, qce.context)
    qcc._sync_priority_map()

    assert len(qcc) == 3
    assert qcc._last() == qce3
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce2
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce1
    qcc._remove_qce(qcc._last())

    assert len(qcc) == 0
