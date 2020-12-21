#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import errno
import logging
import os
import pathlib
import pickle
import time
from abc import ABC
from typing import Dict, ItemsView, Iterator, KeysView, MutableMapping, Optional, Tuple, TypeVar, ValuesView

logger = logging.getLogger(__name__)

K = TypeVar('K')
V = TypeVar('V')


class FLock:
    """A simple file lock.

    It locks a file by creating a lockfile in the same folder with the same name
    with .lck suffix.

    It's not perfect, because it disregards lock files that are older than ttl.
    If 2 threads see a dead lock then they can both acquire the it. Only use if this
    is acceptable.

    Attributes:
        file: The file this lock protects.
        ttl: The max number of seconds a lock is considered to be valid.
        sleep_time: The time we should sleep between busy waiting for lock.
    """

    def __init__(self, file: pathlib.Path, ttl: int = 60, sleep_time: float = 0.05):
        self.file = file
        self.ttl = ttl
        self._lock_file = self.file.parent / (self.file.name + '.lck')
        self.__holding_lock = False
        self.sleep_time = sleep_time
        logger.debug(f"Creating a FLock for: {file}")

    def __enter__(self):
        self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    def acquire(self):
        """Gets lock busy wait style, but since there's a ttl it's guaranteed to return."""
        while True:
            try:
                os.open(self._lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC)
                break
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
                if (time.time() - self._lock_file.stat().st_ctime) > self.ttl:
                    # Note: barging can happen
                    logger.debug(f"Lock file {self._lock_file} is older than {self.ttl}s, deleting it")
                    self._lock_file.unlink()
                    continue
                time.sleep(self.sleep_time)
        self.__holding_lock = True

    def release(self):
        if self.__holding_lock and self._lock_file.exists():
            self._lock_file.unlink()

    def __del__(self):
        self.release()

    def __repr__(self):
        return f"FLock({self.file})"


class SFGenericDictionaryCache(MutableMapping[K, V], ABC):
    """A generic cache that acts like a dictionary with a few extra functions.

    Make sure to overwrite _CACHE_NAME and _generate_default_location to use.
    """

    _CACHE_NAME = 'cache'

    def _generate_default_location(self) -> pathlib.Path:
        """Subclass should implement this."""
        raise NotImplementedError

    def __init__(
            self,
            cache_location: Optional[pathlib.Path] = None,
            cache_expiration: int = 5 * 24 * 60 * 60
    ):
        # Deal with optional arguments/fill in defaults
        if cache_location is None:
            cache_location = self._generate_default_location()

        # Set constants
        self._cache: Dict[K, V] = {}
        # TODO use
        self._cache_expiration: int = cache_expiration
        self._cache_location: pathlib.Path = cache_location
        self._cache_file_lock = FLock(self._cache_location)
        logger.debug(f"Creating {self._CACHE_NAME} located at: {self._cache_location}")

        # Import cache if it already exists
        if self._cache_location.is_file():
            logger.debug(f"{self._CACHE_NAME} found on disk, going to load it")
            self.load()

    def save(self) -> None:
        """Save underlying cache to disk."""
        logger.debug(f"Saving {self._CACHE_NAME} to {self._cache_location}")
        with self._cache_file_lock:
            with self._cache_location.open('wb') as f:
                pickle.dump(self._cache, f)

    def load(self) -> None:
        """Load underlying cache from disk, delete it if it's too old."""
        logger.debug(f"Loading {self._CACHE_NAME} from {self._cache_location}")
        with self._cache_file_lock:
            if (time.time() - self._cache_location.stat().st_mtime) > self._cache_expiration:
                logger.debug(f"{self._CACHE_NAME} is older than {self._cache_expiration}s, deleting it")
                self._cache_location.unlink()
                self._cache = {}
                return
            with self._cache_location.open('rb') as f:
                self._cache = pickle.load(f)

    def _del_file(self) -> None:
        logger.debug(f"Deleting {self._CACHE_NAME} from {self._cache_location}")
        with self._cache_file_lock:
            if self._cache_location.is_file():
                self._cache_location.unlink()

    # The following functions are to make the cache act like the
    # underlying cache dictionary, they act exactly like how dictionaries do

    def keys(self) -> KeysView[K]:
        return self._cache.keys()

    def values(self) -> ValuesView[V]:
        return self._cache.values()

    def items(self) -> ItemsView[K, V]:
        return self._cache.items()

    def get(self, key: K) -> V:
        return self._cache.get(key)

    def clear(self) -> None:
        if self._cache_location.exists():
            self.load()
        self._cache.clear()
        self.save()

    def setdefault(self, key: K, default: Optional[V] = None) -> V:
        if self._cache_location.exists():
            self.load()
        ret = self._cache.setdefault(key, default)
        self.save()
        return ret

    def pop(self, key: K) -> V:
        if self._cache_location.exists():
            self.load()
        ret = self._cache.pop(key)
        self.save()
        return ret

    def popitem(self) -> Tuple[K, V]:
        if self._cache_location.exists():
            self.load()
        ret = self._cache.popitem()
        self.save()
        return ret

    def copy(self) -> Dict[K, V]:
        return self._cache.copy()

    def update(self, mapping: Dict[K, V], **kw) -> None:
        if self._cache_location.exists():
            self.load()
        self._cache.update(mapping, **kw)
        self.save()

    def __getitem__(self, key: K) -> V:
        return self._cache.__getitem__(key)

    def __setitem__(self, key: K, value: V) -> None:
        if self._cache_location.exists():
            self.load()
        self._cache.__setitem__(key, value)
        self.save()

    def __delitem__(self, key: K) -> None:
        if self._cache_location.exists():
            self.load()
        self._cache.__delitem__(key)
        self.save()

    def __contains__(self, key: K) -> bool:
        return self._cache.__contains__(key)

    def __iter__(self) -> Iterator[K]:
        return self._cache.__iter__()

    def __len__(self) -> int:
        return self._cache.__len__()

    def __repr__(self):
        return f"{self._CACHE_NAME}({self._cache_location})"
