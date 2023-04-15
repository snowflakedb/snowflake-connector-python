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
import traceback

from sortedcontainers import SortedSet
from collections import defaultdict

logger = getLogger(__name__)

@total_ordering
class QueryContextElement:
    def __init__(self, id: int, read_timestamp: int, priority: int, context: str):
        # entry with id = 0 is the main entry
        self._id = id
        self._read_timestamp = read_timestamp
        # priority values are 0..N with 0 being the highest priority, in each batch of query context elements we receive from GS, there are no duplicate priorities.
        self._priority = priority
        # OpaqueContext field will be base64 encoded in GS, but it is opaque to client side. Client side should not do decoding/encoding and just store the raw data.
        self._context = context
        

    @property
    def id(self) -> int:
        return self._id
    
    @id.setter
    def id(self, id) -> None:
        self._id = id

    @property
    def read_timestamp(self) -> int:
        return self._read_timestamp

    @read_timestamp.setter
    def read_timestamp(self, timestamp: int) -> None:
        self._read_timestamp = timestamp

    @property
    def priority(self) -> int:
        return self._priority
    
    @priority.setter
    def priority(self, priority: int) -> None:
        self._priority = priority
    
    @property
    def context(self) -> str:
        return self._context

    @context.setter
    def context(self, ctx: str) -> None:
        self._context = ctx

    def __eq__(self, other: QueryContextElement) -> bool:
        # if not isinstance(other, QueryContextElement):
        #     raise NotImplementedError(
        #         f"cannot check equality between QueryContextElement with object of type {type(other)}"
        #     )
        # return (
        #     self._id == other.id
        #     and self._read_timestamp == other.read_timestamp
        #     and self._priority == other.priority
        #     and self._context == other.context
        # )
        
        # context_eq = False
        # if((self._context is not None and other._context is not None and self._context == other._context) or (self._context is None and other._context is None)):
        #     context_eq = True
        
        if isinstance(other, QueryContextElement):
            return self._id == other._id and self._read_timestamp == other._read_timestamp and self._priority == other._priority 
        return False


    def __lt__(self, other: QueryContextElement) -> bool:
        if not isinstance(other, QueryContextElement):
            raise NotImplementedError(
                f"cannot compare QueryContextElement with object of type {type(other)}"
            )
        if self._priority != other._priority:
            return self._priority < other._priority
        if self._read_timestamp != other._read_timestamp:
            return self._read_timestamp < other._read_timestamp
        return self._id < other._id


    def __hash__(self) -> int:
        _hash = 31

        _hash = _hash * 31 + self._id
        _hash += (_hash * 31) + self._read_timestamp
        _hash += (_hash * 31) + self._priority
        # if self._context:
        #     _hash += (_hash * 31) + int.from_bytes(md5(self._context.encode('utf-8')).digest(), "big")
        return _hash
    
    
    # def __hash__(self):
    #     id_hash = hash(self._id)
    #     read_timestamp_hash = hash(self._read_timestamp)
    #     priority_hash = hash(self._priority)
    #     context_hash = hash(self._context)

    #     combined_hash = (
    #         (id_hash << 1) ^ read_timestamp_hash ^ (priority_hash << 3) ^ context_hash
    #     )
    #     print("{} __hash__={}".format(self, combined_hash))
    #     return combined_hash
    def __str__(self) -> str:
        return f"({self._id}({type(self._id)}), {self._read_timestamp}({type(self._read_timestamp)}), {self._priority}({type(self._priority)}, context={self._context}))"
    
    def __repr__(self):
        return f"QueryContextElement(id={self._id}, read_timestamp={self._read_timestamp}, priority={self._priority}, context={self._context})"



class QueryContextCache:
    def __init__(self, capacity: int):
        self._capacity = capacity
        self._id_map: dict[int, QueryContextElement] = {}
        self._priority_map: dict[int,  QueryContextElement] = {}
        # when merge a list of incoming query context elements, their priority could be changed. We need to store 
        # the new priority in a separate map and sync it with the original map after merging all the elements.
        self._priority_map_new_pass: dict[int,  QueryContextElement] = {}

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
        # store the qce with new priority in a separate map, sync it with the original map after merging all the elements.
        self._priority_map_new_pass[qce.priority] = qce
        self._tree_set.add(qce)

    def _remove_qce(self, qce: QueryContextElement) -> None:
        self._id_map.pop(qce.id)
        print("remove priority map")
        self._priority_map.pop(qce.priority)
        print("finish remove priority map")
        for element in self._tree_set:
            print(element)
        import pdb
        pdb.set_trace()
        self._tree_set.remove(qce)

        # for element in self._tree_set:
        #     print("compare {} and {} = {}".format(qce, element, qce.__eq__(element)))
        #     if(qce.__eq__(element)):
        #         self._tree_set.remove(element)
        print("finish remove tree set")

    def _replace_qce(
        self, old_qce: QueryContextElement, new_qce: QueryContextElement
    ) -> None:
        print("old qce {}".format(old_qce))
        print("new qce {}".format(new_qce))
        self._remove_qce(old_qce)
        self._add_qce(new_qce)
    
    def _sync_priority_map(self):
        # sync the new priority map with the original map
        for priority, qce in self._priority_map_new_pass.items():
            self._priority_map[priority] = qce
        # clear the new priority map for merging the next batch of elements
        print("finish sync priority map")
        self._priority_map_new_pass.clear()
                

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
                    print("priority changed")
                    # change in priority caused replacement of query context
                    new_qce = QueryContextElement(id, read_timestamp, priority, context)
                    self._replace_qce(qce, new_qce)
            elif read_timestamp == qce.read_timestamp and priority != qce.priority:
                new_qce = QueryContextElement(id, read_timestamp, priority, context)
                self._replace_qce(qce, new_qce)
        else:
            new_qce = QueryContextElement(id, read_timestamp, priority, context)
            if priority in self._priority_map:
                print("new id with priority changed")
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
                data = {
                    "entries": [
                        {
                            "id": qce.id,
                            "timestamp": qce.read_timestamp,
                            "priority": qce.priority,
                            "context": qce.context,
                        }
                        for idx, qce in enumerate(self._tree_set)
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
                        logger.debug("timestamp type error")
                        raise TypeError(f"Invalid type for 'timestamp' field: Expected int, got {type(entry['timestamp'])}")
                    if not isinstance(entry.get("priority"), int):
                        logger.debug("priority type error")
                        raise TypeError(f"Invalid type for 'priority' field: Expected int, got {type(entry['priority'])}")
                    
                    context = entry.get("context", None) # OpaqueContext field currently is empty from GS side.
                
                    if context is not None and not isinstance(context, str):
                        logger.debug("context type error")
                        raise TypeError(f"Invalid type for 'context' field: Expected str, got {type(entry['context'])}")
                    self.merge(
                        entry.get("id"),
                        entry.get("timestamp"),
                        entry.get("priority"),
                        context, 
                    )
                # We need to sync the priority map after merging the list of all entries, and clear the intermediate priority map for next round
                self._sync_priority_map()
            except Exception as e:
                print(f"deserialize_json_dict: Exception = {e}")
                logger.debug(f"deserialize_json_dict: Exception = {e}")
                # clear cache due to incomplete merge
                self.clear_cache()

            self.check_cache_capacity()
            logger.debug("deserialize_json_dict() returns")
            self.log_cache_entries()

    def log_cache_entries(self) -> None:
        if logger.level == DEBUG:
            for qce in self._tree_set:
                logger.debug(
                    f"Cache Entry: id: {qce.id}, read_timestamp: {qce.read_timestamp}, priority: {qce.priority}"
                )

    def get_size(self) -> int:
        return len(self._tree_set)

