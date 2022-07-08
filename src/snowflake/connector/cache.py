#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import datetime
from collections.abc import Iterator
from threading import Lock
from typing import Generic, TypeVar

from typing_extensions import NamedTuple, Self

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

    Notes:
    - Unlike normal dictionaries keys, values and items return list
      materialized at call time, instead of returning a view object.
    """

    def __init__(
        self,
        entry_lifetime: int = 60 * 60 * 24,  # 1 day in seconds
    ) -> None:
        self._entry_lifetime = datetime.timedelta(seconds=entry_lifetime)
        self._cache: dict[K, CacheEntry[V]] = {}
        self._lock = Lock()

    @classmethod
    def from_dict(
        cls,
        _dict: dict[K, V],
        **kw,
    ) -> Self:
        cache = cls(**kw)
        for k, v in _dict.items():
            cache[k] = v
        return cache

    def __getitem(
        self,
        k: K,
    ) -> V:
        """Non-locking version of __getitem__.

        This should only be used by internal functions when already
        holding self._lock.
        """
        t, v = self._cache[k]
        if is_expired(t):
            del self._cache[k]
            raise KeyError
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

    def __getitem__(
        self,
        k: K,
    ) -> V:
        """Returns an element if it hasn't expired yet in a thread-safe way."""
        with self._lock:
            return self.__getitem(k)

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
        keys: list[K] = []
        with self._lock:
            for k in list(self._cache.keys()):
                try:
                    _ = self.__getitem(k)
                    keys.append(k)
                except KeyError:
                    continue
        return keys

    def __items(self) -> list[tuple[K, V]]:
        """Non-locking version of items.

        This should only be used by internal functions when already
        holding self._lock.
        """
        values: list[tuple[K, V]] = []
        for k in list(self._cache.keys()):
            try:
                v = self.__getitem(k)
                values.append((k, v))
            except KeyError:
                continue
        return values

    def items(self) -> list[tuple[K, V]]:
        with self._lock:
            return self.__items()

    def values(self) -> list[V]:
        values: list[V] = []
        with self._lock:
            for k in list(self._cache.keys()):
                try:
                    v = self.__getitem(k)
                    values.append(v)
                except KeyError:
                    continue
        return values

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

    def __delitem__(
        self,
        key: K,
    ) -> None:
        with self._lock:
            del self._cache[key]

    def __contains__(
        self,
        key: K,
    ) -> bool:
        with self._lock:
            if key in self._cache.keys():
                try:
                    self.__getitem(key)
                    return True
                except KeyError:
                    # Fall through
                    pass
        return False

    def update(
        self,
        other: dict[K, V] | SFDictCache[K, V],
    ) -> None:
        t = now() + self._entry_lifetime

        if isinstance(other, (SFDictCache, dict)):
            to_insert: dict[K, CacheEntry[V]] = {
                k: CacheEntry(expiry=t, entry=v) for k, v in other.items()
            }
            with self._lock:
                self._cache.update(to_insert)
        else:
            raise TypeError

    def _clear_expired_entries(self) -> None:
        with self._lock:
            for k in self._cache.keys():
                try:
                    self.__getitem(k)
                except KeyError:
                    continue
