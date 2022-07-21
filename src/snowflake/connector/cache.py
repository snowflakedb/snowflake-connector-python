#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import datetime
from collections.abc import Iterator
from threading import Lock
from typing import Generic, TypeVar

from typing_extensions import NamedTuple, Self

from . import constants

now = datetime.datetime.now

T = TypeVar("T")


class CacheEntry(NamedTuple, Generic[T]):
    expiry: datetime.datetime
    entry: T


K = TypeVar("K")
V = TypeVar("V")


def is_expired(d: datetime.datetime) -> bool:
    return now() >= d


class SFDictCache(Generic[K, V]):
    """A generic in-memory cache that acts somewhat like a dictionary.

    Unlike normal dictionaries keys(), values() and items() return list materialized
    at call time, unlike normal dictionaries that return a view object.
    """

    def __init__(
        self,
        entry_lifetime: int = constants.DAY_IN_SECONDS,
    ) -> None:
        self._entry_lifetime = datetime.timedelta(seconds=entry_lifetime)
        self._cache: dict[K, CacheEntry[V]] = {}
        self._lock = Lock()
        self._reset_telemetry()

    @classmethod
    def from_dict(
        cls,
        _dict: dict[K, V],
        **kw,
    ) -> Self:
        """Create an dictionary cache from an already existing dictionary.

        Note that the same references will be stored in the cache than in
        the dictionary provided.
        """
        cache = cls(**kw)
        for k, v in _dict.items():
            cache[k] = v
        return cache

    def __getitem(
        self,
        k: K,
        *,
        should_record_hits: bool = True,
    ) -> V:
        """Non-locking version of __getitem__.

        This should only be used by internal functions when already
        holding self._lock.
        """
        try:
            t, v = self._cache[k]
        except KeyError:
            self._miss(k)
            raise
        if is_expired(t):
            self._expiration(k)
            self.__delitem(k)
            raise KeyError
        if should_record_hits:
            self._hit(k)
        return v

    def __setitem(
        self,
        k: K,
        v: V,
    ) -> None:
        """Non-locking version of __setitem__.

        This should only be used by internal functions when already
        holding self._lock.
        """
        self._cache[k] = CacheEntry(
            expiry=now() + self._entry_lifetime,
            entry=v,
        )
        self.telemetry["size"] = len(self._cache)

    def __getitem__(
        self,
        k: K,
    ) -> V:
        """Returns an element if it hasn't expired yet in a thread-safe way."""
        with self._lock:
            return self.__getitem(k, should_record_hits=True)

    def __setitem__(
        self,
        k: K,
        v: V,
    ) -> None:
        """Inserts an element in a thread-safe way."""
        with self._lock:
            self.__setitem(k, v)

    def __iter__(self) -> Iterator[K]:
        return iter(self.keys())

    def keys(self) -> list[K]:
        return [k for k, _ in self.items()]

    def items(self) -> list[tuple[K, V]]:
        with self._lock:
            values: list[tuple[K, V]] = []
            for k in list(self._cache.keys()):
                try:
                    # TODO: this function could be further optimized by removing
                    #  the need here to call __getitem here and call se;f._cache.keys()
                    v = self.__getitem(k, should_record_hits=False)
                    values.append((k, v))
                except KeyError:
                    continue
        return values

    def values(self) -> list[V]:
        return [v for _, v in self.items()]

    def get(
        self,
        k: K,
        default: V | None = None,
    ) -> V | None:
        try:
            return self[k]
        except KeyError:
            return default

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._reset_telemetry()

    def __delitem(
        self,
        key: K,
    ) -> None:
        """Non-locking version of __delitem__.

        This should only be used by internal functions when already
        holding self._lock.
        """
        del self._cache[key]
        self.telemetry["size"] = len(self._cache)

    def __delitem__(
        self,
        key: K,
    ) -> None:
        with self._lock:
            self.__delitem(key)

    def __contains__(
        self,
        key: K,
    ) -> bool:
        with self._lock:
            try:
                self.__getitem(key, should_record_hits=True)
                return True
            except KeyError:
                # Fall through
                return False

    def update(
        self,
        other: dict[K, V] | SFDictCache[K, V],
    ) -> None:
        """Insert multiple values at the same time.

        If this function is given a dictionary, expiration timestamps
        will be all the same a self._entry_lifetime form now. If it's
        given another SFDictCache then the timestamps will be taken
        from the other cache.
        """
        if isinstance(other, dict):
            t = now() + self._entry_lifetime
            to_insert: dict[K, CacheEntry[V]] = {
                k: CacheEntry(expiry=t, entry=v) for k, v in other.items()
            }
        elif isinstance(other, SFDictCache):
            to_insert: dict[K, CacheEntry[V]] = {k: v for k, v in other._cache.items()}
        else:
            raise TypeError
        with self._lock:
            self._cache.update(to_insert)
            self.telemetry["size"] = len(self._cache)

    def _clear_expired_entries(self) -> None:
        with self._lock:
            for k in self._cache.keys():
                try:
                    self.__getitem(k, should_record_hits=False)
                except KeyError:
                    continue
            self.telemetry["size"] = len(self._cache)

    # Telemetry related functions, these can be plugged by child classes
    def _reset_telemetry(self) -> None:
        """(Re)set telemetry fields.

        This function will be called by the initalizer and other functions that should
        reset telemtry entries.
        """
        self.telemetry = {
            "hit": 0,
            "miss": 0,
            "expiration": 0,
            "size": 0,
        }

    def _hit(self, k: K) -> None:
        """This function gets called when a hit occurs.

        Functions that hit every entry (like values) is not going to count.

        Note that while this function does not interact with lock, but it's only
        called from contexts where the lock is already held.
        """
        self.telemetry["hit"] += 1

    def _miss(self, k: K) -> None:
        """This function gets called when a miss occurs.

        Note that while this function does not interact with lock, but it's only
        called from contexts where the lock is already held.
        """
        self.telemetry["miss"] += 1

    def _expiration(self, k: K) -> None:
        """This function gets called when an expiration occurs.

        Note that while this function does not interact with lock, but it's only
        called from contexts where the lock is already held.
        """
        self.telemetry["expiration"] += 1
