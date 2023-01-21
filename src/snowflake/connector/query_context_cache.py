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

import pyarrow as pa
from sortedcontainers import SortedSet

logger = getLogger(__name__)


@total_ordering
class QueryContextElement:
    def __init__(self, id: int, read_timestamp: int, priority: int, context: bytearray):
        self._id = id
        self._read_timestamp = read_timestamp
        # priority values are 0..N with 0 being the highest priority
        self._priority = priority
        if context is None:
            self._context = bytearray(b"")
        else:
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
    def context(self) -> bytearray:
        return self._context

    @context.setter
    def context(self, ctx: bytearray) -> None:
        if ctx is None:
            self._context = bytearray(b"")
        else:
            self._context = ctx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QueryContextElement):
            # TODO:
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
        _hash += (_hash * 31) + int.from_bytes(md5(self._context).digest(), "big")
        return _hash

    def __str__(self) -> str:
        return f"({self._id}, {self._read_timestamp}, {self._priority})"


class QueryContextCache:
    QUERY_CONTEXT_SCHEMA = pa.schema(
        [
            pa.field("id", pa.int64(), nullable=False),
            pa.field("timestamp", pa.int64(), nullable=False),
            pa.field("priority", pa.int64(), nullable=False),
            pa.field("context", pa.binary(), nullable=True),
        ]
    )

    def __init__(self, capacity: int):
        self._capacity = capacity
        self._id_map: dict[int, QueryContextElement] = {}
        self._priority_map: dict[int, QueryContextElement] = {}
        # stores elements sorted by priority. Element with
        # least priority value has the highest priority
        self._treeset: set[QueryContextElement] = SortedSet()
        self._lock = Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def _add_qce(self, qce: QueryContextElement) -> None:
        self._id_map[qce.id] = qce
        self._priority_map[qce.priority] = qce
        self._treeset.add(qce)

    def _remove_qce(self, qce: QueryContextElement) -> None:
        self._id_map.pop(qce.id)
        self._priority_map.pop(qce.priority)
        self._treeset.remove(qce)

    def _replace_qce(
        self, old_qce: QueryContextElement, new_qce: QueryContextElement
    ) -> None:
        self._remove_qce(old_qce)
        self._add_qce(new_qce)

    def merge(
        self, id: int, read_timestamp: int, priority: int, context: bytearray
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
            f"check_cache_capacity() called. treeSet size is {len(self._treeset)} and cache capacity is {self.capacity}"
        )

        while len(self._treeset) > self.capacity:
            # remove the qce with highest priority value => element with least priority
            qce = self._treeset[-1]
            self._remove_qce(qce)

        logger.debug(
            f"check_cache_capacity() returns. treeSet size is {len(self._treeset)} and cache capacity is {self.capacity}"
        )

    def clear_cache(self) -> None:
        logger.debug("clear_cache() called")
        self._id_map.clear()
        self._priority_map.clear()
        self._treeset.clear()

    def _get_elements(self) -> set[QueryContextElement]:
        return self._treeset

    def _last(self) -> QueryContextElement:
        return self._treeset[-1]

    def deserialize_from_arrow_base64(self, data: str) -> None:
        with self._lock:
            logger.debug(
                f"deserialize_from_arrow_base64() called: data from server: {data}"
            )
            self.log_cache_entries()

            if data is None or len(data) == 0:
                self.clear_cache()
                logger.debug("deserialize_from_arrow_base64() returns")
                self.log_cache_entries()
                return

            decoded_data = b64decode(data)
            input = BytesIO(decoded_data)
            try:
                with pa.ipc.open_stream(input) as reader:
                    for record_batch in reader:
                        record_dict = record_batch.to_pydict()
                        for i in range(len(record_batch)):
                            self.merge(
                                record_dict["id"][i],
                                record_dict["timestamp"][i],
                                record_dict["priority"][i],
                                record_dict["context"][i],
                            )
            except Exception as e:
                logger.debug(f"deserialize_from_arrow_base64: Exception = {e}")
                # clear cache due to incomplete merge
                self.clear_cache()

            self.check_cache_capacity()
            logger.debug("deserialize_from_arrow_base64() returns")
            self.log_cache_entries()

    def serialize_to_arrow_base64(self) -> str:
        with self._lock:
            logger.debug("serialize_to_arrow_base64() called")
            self.log_cache_entries()

            if len(self._treeset) == 0:
                # TODO: should this be ""
                return None

            try:
                stream = BytesIO()
                id_vals = []
                timestamp_vals = []
                priority_vals = []
                context_vals = []
                for qce in self._treeset:
                    id_vals.append(qce.id)
                    timestamp_vals.append(qce.read_timestamp)
                    priority_vals.append(qce.priority)
                    context_vals.append(qce.context)
                with pa.ipc.RecordBatchStreamWriter(
                    stream, self.QUERY_CONTEXT_SCHEMA
                ) as writer:
                    id_array = pa.array(id_vals, type=pa.int64())
                    timestamp_array = pa.array(timestamp_vals, type=pa.int64())
                    priority_array = pa.array(priority_vals, type=pa.int64())
                    context_array = pa.array(context_vals, type=pa.binary())
                    record_batch = pa.record_batch(
                        [id_array, timestamp_array, priority_array, context_array],
                        schema=self.QUERY_CONTEXT_SCHEMA,
                    )
                    writer.write_batch(record_batch)

                stream.seek(0)
                # use same encoding use on jdbc driver
                data = b64encode(stream.read()).decode("iso-8859-1")
                stream.close()

                logger.debug(
                    f"serialize_to_arrow_base64(): data to send to server {data}"
                )
                return data.decode("utf-8")
            except Exception as e:
                logger.debug(f"serialize_to_arrow_base64(): Exception {e}")
                # TODO: should this be ""
                return None

    def log_cache_entries(self) -> None:
        if logger.level == DEBUG:
            for qce in self._treeset:
                logger.debug(
                    f"Cache Entry: id: {qce.id}, read_timestamp: {qce.read_timestamp}, priority: {qce.priority}"
                )

    def get_size(self) -> int:
        return len(self._treeset)
