#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
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

@total_ordering
class QueryContextElement:
    def __init__(self, id: int, read_timestamp: int, priority: int, context: str):
        # entry with id = 0 is the main entry
        self._id = id
        self._read_timestamp = read_timestamp
        # priority values are 0..N with 0 being the highest priority
        self._priority = priority
        # OpaqueContext field will be base64 encoded in GS, but it is opaque to client side. Client side should not do decoding/encoding and just store the raw data.
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
        if self._priority != other._priority:
            return self._priority < other._priority
        if self._id != other._id:
            return self._id < other._id
        return self._read_timestamp < other._read_timestamp


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
                data = {
                    "entries": [
                        {
                            "id": id_vals[i],
                            "timestamp": timestamp_vals[i],
                            "priority": priority_vals[i],
                            "context": context_vals[i],
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

    def deserialize_json_dict(self, data) -> None:
        with self._lock:
            logger.debug(
                f"deserialize_json_dict() called: data from server: {data}"
            )
            self.log_cache_entries()
            
            if data is None or len(data) == 0:
                self.clear_cache()
                logger.debug("deserialize_json_dict() returns")
                self.log_cache_entries()
                return
            
            try:
                # Deserialize the entries. The first entry with priority 0 is the main entry. On python
                # connector side, we save all entries into one list to simplify the logic. When python
                # connector receives HTTP response, the data["queryContext"] field has been converted
                # from JSON to dict type automatically, so for this function we deserialize from python
                # dict directly. Below is an example QueryContext dict.
                # {
                #   "entries": [
                #    {
                #     "id": 0,    
                #     "read_timestamp": 123456789,
                #     "priority": 0,
                #     "context": "base64 encoded context"
                #    },
                #     {
                #       "id": 1,
                #       "read_timestamp": 123456789,
                #       "priority": 1,
                #       "context": "base64 encoded context"
                #     },
                #     {
                #       "id": 2,
                #       "read_timestamp": 123456789,
                #       "priority": 2,
                #       "context": "base64 encoded context"
                #     }
                #   ]
                # }
                
                # Deserialize entries
                entries = data.get("entries", None)
                for entry in entries:
                    logger.debug("deserialize {}".format(entry))
                    if not isinstance(entry.get("id"), int):
                        logger.debug("id type error")
                        raise TypeError(f"Invalid type for 'id' field: Expected int, got {type(entry['id'])}")
                    if not isinstance(entry.get("timestamp"), int):
                        raise TypeError(f"Invalid type for 'timestamp' field: Expected int, got {type(entry['timestamp'])}")
                    if not isinstance(entry.get("priority"), int):
                        raise TypeError(f"Invalid type for 'priority' field: Expected int, got {type(entry['priority'])}")
                    
                    context = entry.get("context", None) # OpaqueContext field currently is empty from GS side.
                
                    if context is not None and not isinstance(context, str):
                        raise TypeError(f"Invalid type for 'context' field: Expected str, got {type(entry['context'])}")

                    self.merge(
                        entry.get("id"),
                        entry.get("timestamp"),
                        entry.get("priority"),
                        context, 
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
        return len(self._tree_set)

    def get_elements(self, ids, timestamps, priorities, contexts) -> None:
        for idx, qce in enumerate(self._tree_set):
            ids[idx] = qce.id
            timestamps[idx] = qce.read_timestamp
            priorities[idx] = qce.priority
            contexts[idx] = qce.context
