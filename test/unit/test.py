

from __future__ import annotations

from base64 import b64decode, b64encode
from functools import total_ordering
from hashlib import md5
from io import BytesIO
from logging import DEBUG, getLogger
from threading import Lock
import json

from sortedcontainers import SortedSet

logger = getLogger(__name__)



installed_pandas = True

try:
    from snowflake.connector.options import pandas
except ImportError:
    installed_pandas = False
    pandas = None


@total_ordering
class QueryContextElement:
    def __init__(self, id: int, read_timestamp: int, priority: int, context: str):
        self._id = id
        self._read_timestamp = read_timestamp
        # priority values are 0..N with 0 being the highest priority
        self._priority = priority
        self._context = context

    @property
    def id(self) -> int:
        return self._id

    @property
    def read_timestamp(self) -> int:
        return self._read_timestamp

    @read_timestamp.setter
    def read_timestamp(self, timestamp: int) -> None:
        self._read_timestamp = timestamp

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def context(self) -> str:
        return self._context

    @context.setter
    def context(self, ctx: str) -> None:
        self._context = ctx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QueryContextElement):
            return False
        return (
            self._id == other.id
            and self._read_timestamp == other.read_timestamp
            and self._priority == other.priority
            and self._context == other.context
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, QueryContextElement):
            raise NotImplementedError(
                f"cannot compare QueryContextElement with object of type {type(other)}"
            )
        return self._priority < other.priority

    def __hash__(self) -> int:
        _hash = 31

        _hash = _hash * 31 + self._id
        _hash += (_hash * 31) + self._read_timestamp
        _hash += (_hash * 31) + self._priority
        if self._context:
            _hash += (_hash * 31) + int.from_bytes(md5(self._context.encode('utf-8')).digest(), "big")
        return _hash

    def __str__(self) -> str:
        return f"({self._id}, {self._read_timestamp}, {self._priority})"


class QueryContextCache:
    def __init__(self, capacity: int):
        self._capacity = capacity
        self._id_map: dict[int, QueryContextElement] = {}
        self._priority_map: dict[int, QueryContextElement] = {}
        # stores elements sorted by priority. Element with
        # least priority value has the highest priority
        self._tree_set: set[QueryContextElement] = SortedSet()
        self._lock = Lock()
        self._data: str = None

    @property
    def capacity(self) -> int:
        return self._capacity

    def _add_qce(self, qce: QueryContextElement) -> None:
        self._id_map[qce.id] = qce
        self._priority_map[qce.priority] = qce
        self._tree_set.add(qce)

    def _remove_qce(self, qce: QueryContextElement) -> None:
        self._id_map.pop(qce.id)
        self._priority_map.pop(qce.priority)
        self._tree_set.remove(qce)

    def _replace_qce(
        self, old_qce: QueryContextElement, new_qce: QueryContextElement
    ) -> None:
        self._remove_qce(old_qce)
        self._add_qce(new_qce)

    def merge(
        self, id: int, read_timestamp: int, priority: int, context: str
    ) -> None:
        if id in self._id_map:
            qce = self._id_map[id]
            # when id if found in cache and we are operating on a more recent timestamp
            if read_timestamp > qce.read_timestamp:
                if qce.priority == priority:
                    # same priority updates the current context object
                    qce.read_timestamp = read_timestamp
                    qce.context = context
                else:
                    # change in priority caused replacement of query context
                    new_qce = QueryContextElement(id, read_timestamp, priority, context)
                    self._replace_qce(qce, new_qce)
            elif read_timestamp == qce.read_timestamp and priority != qce.priority:
                new_qce = QueryContextElement(id, read_timestamp, priority, context)
                self._replace_qce(qce, new_qce)
        else:
            new_qce = QueryContextElement(id, read_timestamp, priority, context)
            if priority in self._priority_map:
                old_qce = self._priority_map[priority]
                self._replace_qce(old_qce, new_qce)
            else:
                self._add_qce(new_qce)

    def check_cache_capacity(self) -> None:
        logger.debug(
            f"check_cache_capacity() called. treeSet size is {len(self._tree_set)} and cache capacity is {self.capacity}"
        )

        while len(self._tree_set) > self.capacity:
            # remove the qce with highest priority value => element with least priority
            qce = self._tree_set[-1]
            self._remove_qce(qce)

        logger.debug(
            f"check_cache_capacity() returns. treeSet size is {len(self._tree_set)} and cache capacity is {self.capacity}"
        )

    def clear_cache(self) -> None:
        logger.debug("clear_cache() called")
        self._id_map.clear()
        self._priority_map.clear()
        self._tree_set.clear()

    def _get_elements(self) -> set[QueryContextElement]:
        return self._tree_set

    def _last(self) -> QueryContextElement:
        return self._tree_set[-1]
    
    def serialize_to_json(self) -> str:
        if not installed_pandas:
            return self._data

        with self._lock:
            logger.debug("serialize_to_json() called")
            self.log_cache_entries()

            if len(self._tree_set) == 0:
                return None

            try:
                size = self.get_size()
                id_vals = [None] * size
                timestamp_vals = [None] * size
                priority_vals = [None] * size
                context_vals = [None] * size
                self.get_elements(id_vals, timestamp_vals, priority_vals, context_vals)
                data = {}
                if(size >= 1):
                    data = {
                        "entries": [
                            {
                                "id": id_vals[i],
                                "timestamp": timestamp_vals[i],
                                "priority": priority_vals[i],
                                "context": b64encode(context_vals[i]).decode("iso-8859-1"),
                            }
                            for i in range(0, size)
                        ]
                    }

                # Serialize the data to JSON
                serialized_data = json.dumps(data)

                logger.debug(
                    f"serialize_to_json(): data to send to server {serialized_data}"
                )

                return serialized_data
            except Exception as e:
                logger.debug(f"serialize_to_json(): Exception {e}")
                return None

    def deserialize_json_string(self, json_string: str) -> None:
        if not installed_pandas:
            logger.debug("not install pandas")
            print("not install pandas")
            self._data = json_string
            return
        with self._lock:
            logger.debug(
                f"deserialize_from_json() called: data from server: {json_string}"
            )
            self.log_cache_entries()
            assert(json_string is None, "none json string")
            
            if json_string is None or len(json_string) == 0:
                self.clear_cache()
                logger.debug("deserialize_from_json() returns")
                self.log_cache_entries()
                return
            
            try:
                data = json.loads(json_string)
                # main_entry and entries are all stored in a list of QueryContextEntry to simplify
                if("entries" in data):
                    # Deserialize entries
                    entries = data["entries"]
                    for entry in entries:
                        self.merge(
                            entry["id"],
                            entry["timestamp"],
                            entry["priority"],
                            entry["context"],
                        )
            except Exception as e:
                logger.debug(f"deserialize_from_json: Exception = {e}")
                # clear cache due to incomplete merge
                self.clear_cache()

            self.check_cache_capacity()
            logger.debug("deserialize_from_json() returns")
            self.log_cache_entries()

    def log_cache_entries(self) -> None:
        if logger.level == DEBUG:
            for qce in self._tree_set:
                logger.debug(
                    f"Cache Entry: id: {qce.id}, read_timestamp: {qce.read_timestamp}, priority: {qce.priority}"
                )

    def get_size(self) -> int:
        logger.debug("size={}".format(len(self._tree_set)))
        return len(self._tree_set)

    def get_elements(self, ids, timestamps, priorities, contexts) -> None:
        for idx, qce in enumerate(self._tree_set):
            ids[idx] = qce.id
            timestamps[idx] = qce.read_timestamp
            priorities[idx] = qce.priority
            contexts[idx] = qce.context





from random import shuffle

installed_pandas = True

try:
    from snowflake.connector.options import pandas
except ImportError:
    installed_pandas = False
    pandas = None


import logging
import os

for logger_name in ('snowflake.connector',):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)


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


def expected_data() -> ExpectedQCCData:
    data = ExpectedQCCData(MAX_CAPACITY)
    return data


def expected_data_with_null_context() -> ExpectedQCCData:
    data = ExpectedQCCData(MAX_CAPACITY, context=None)
    yield data
    data.reset_data()


def qcc_with_no_data() -> QueryContextCache:
    return QueryContextCache(MAX_CAPACITY)


def qcc_with_data(
    qcc_with_no_data: QueryContextCache, expected_data: ExpectedQCCData
) -> QueryContextCache:
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.merge(
            expected_data.ids[i],
            expected_data.timestamps[i],
            expected_data.priorities[i],
            expected_data.contexts[i],
        )
    return qcc_with_no_data


def qcc_with_data_random_order(
    qcc_with_no_data: QueryContextCache,
    expected_data: ExpectedQCCData,
) -> QueryContextCache:
    expected_data.shuffle_data()
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.merge(
            expected_data.ids[i],
            expected_data.timestamps[i],
            expected_data.priorities[i],
            expected_data.contexts[i],
        )
    yield qcc_with_no_data
    qcc_with_no_data.clear_cache()


def qcc_with_data_null_context(
    qcc_with_no_data: QueryContextCache,
    expected_data_with_null_context: ExpectedQCCData,
):
    for i in range(MAX_CAPACITY):
        qcc_with_no_data.merge(
            expected_data_with_null_context.ids[i],
            expected_data_with_null_context.timestamps[i],
            expected_data_with_null_context.priorities[i],
            expected_data_with_null_context.contexts[i],
        )
    yield qcc_with_no_data
    qcc_with_no_data.clear_cache()


def assert_cache_with_data(
    qcc: QueryContextCache, expected_data: ExpectedQCCData
) -> None:
    assert qcc.get_size() == MAX_CAPACITY

    ids = [None] * MAX_CAPACITY
    timestamps = [None] * MAX_CAPACITY
    priorities = [None] * MAX_CAPACITY
    contexts = [None] * MAX_CAPACITY

    qcc.get_elements(ids, timestamps, priorities, contexts)
    for i in range(MAX_CAPACITY):
        assert expected_data.ids[i] == ids[i]
        assert expected_data.timestamps[i] == timestamps[i]
        assert expected_data.priorities[i] == priorities[i]
        assert expected_data.contexts[i] == contexts[i]


def test_is_empty(qcc_with_no_data: QueryContextCache):
    assert qcc_with_no_data.get_size() == 0


def test_with_data(qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData):
    assert_cache_with_data(qcc_with_data, expected_data)


def test_with_data_in_random_order(
    qcc_with_data_random_order: QueryContextCache, expected_data: ExpectedQCCData
):
    expected_data.reset_data()
    assert_cache_with_data(qcc_with_data_random_order, expected_data)


def test_check_cache_capacity(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    qcc_with_data.merge(
        BASE_ID + MAX_CAPACITY,
        BASE_READ_TIMESTAMP + MAX_CAPACITY,
        BASE_PRIORITY + MAX_CAPACITY,
        CONTEXT,
    )
    qcc_with_data.check_cache_capacity()

    assert_cache_with_data(qcc_with_data, expected_data)


def test_update_timestamp(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    update_id = 1
    qcc_with_data.merge(
        BASE_ID + update_id,
        BASE_READ_TIMESTAMP + update_id + 10,
        BASE_PRIORITY + update_id,
        CONTEXT,
    )
    expected_data.timestamps[update_id] = BASE_READ_TIMESTAMP + update_id + 10
    assert_cache_with_data(qcc_with_data, expected_data)


def test_update_priority(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    update_id = 3
    updated_priority = BASE_PRIORITY + update_id + 7
    qcc_with_data.merge(
        BASE_ID + update_id, BASE_READ_TIMESTAMP + update_id, updated_priority, CONTEXT
    )

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
    qcc_with_data.merge(BASE_ID + i, BASE_READ_TIMESTAMP + i, updated_priority, CONTEXT)

    expected_data.ids[1] = BASE_ID + i
    expected_data.timestamps[1] = BASE_READ_TIMESTAMP + i
    assert_cache_with_data(qcc_with_data, expected_data)


def test_same_id_with_stale_timestamp(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    i = 2
    qcc_with_data.merge(
        BASE_ID + i, BASE_READ_TIMESTAMP + i - 10, BASE_PRIORITY + i, CONTEXT
    )
    qcc_with_data.check_cache_capacity()

    assert_cache_with_data(qcc_with_data, expected_data)


def test_empty_cache_with_null_data(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)

    qcc_with_data.deserialize_json_string(None)
    assert qcc_with_data.get_size() == 0

qcc_with_no_data = qcc_with_no_data()
expected_data = expected_data()
qcc_with_data = qcc_with_data(qcc_with_no_data, expected_data)
test_empty_cache_with_null_data(qcc_with_data, expected_data)


def test_empty_cache_with_empty_response_data(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)    

    qcc_with_data.deserialize_json_string("")
    assert qcc_with_data.get_size() == 0


def test_serialization_deserialization_with_null_context(
    qcc_with_data_null_context: QueryContextCache,
    expected_data_with_null_context: ExpectedQCCData,
):
    assert_cache_with_data(qcc_with_data_null_context, expected_data_with_null_context)

    data = qcc_with_data_null_context.serialize_to_json()
    qcc_with_data_null_context.clear_cache()
    assert qcc_with_data_null_context.get_size() == 0

    qcc_with_data_null_context.deserialize_json_string(data)
    assert_cache_with_data(qcc_with_data_null_context, expected_data_with_null_context)

test_serialization_deserialization_with_null_context(qcc_with_data, expected_data)

def test_serialization_deserialization(
    qcc_with_data: QueryContextCache, expected_data: ExpectedQCCData
):
    assert_cache_with_data(qcc_with_data, expected_data)

    data = qcc_with_data.serialize_to_json()
    qcc_with_data.clear_cache()
    assert qcc_with_data.get_size() == 0

    qcc_with_data.deserialize_json_string(data)
    assert_cache_with_data(qcc_with_data, expected_data)


def test_eviction_order():
    qce1 = QueryContextElement(id=1, read_timestamp=13323, priority=1, context=None)
    qce2 = QueryContextElement(
        id=2, read_timestamp=15522, priority=4, context="")
    
    qce3 = QueryContextElement(
        id=3, read_timestamp=8383, priority=99, context="generic context")
    
    qce_list = [qce1, qce2, qce3]
    qcc = QueryContextCache(5)
    for qce in qce_list:
        qcc.merge(qce.id, qce.read_timestamp, qce.priority, qce.context)

    assert qcc.get_size() == 3
    assert qcc._last() == qce3
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce2
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce1
    qcc._remove_qce(qcc._last())

    assert qcc.get_size() == 0
