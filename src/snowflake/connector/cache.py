#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import copy
import datetime
import logging
from collections.abc import Iterator, MutableMapping, ValuesView
from threading import Lock
from typing import Generic, ItemsView, KeysView, NamedTuple, TypeVar

logger = logging.getLogger(__name__)
now = datetime.datetime.now

T = TypeVar("T")


class CacheEntry(NamedTuple):
    expiry: datetime.datetime
    entry: T


# Hack, because NamedTuples cannot inherit from multiple classes
class CacheEntry(CacheEntry, Generic[T]):
    pass


K = TypeVar("K")
V = TypeVar("V")
Self = TypeVar("Self", bound="SFDictCache")


class SFDictCache(MutableMapping[K, V]):
    """A generic cache that acts like a dictionary with a few extra functions."""

    def __init__(
        self,
        entry_lifetime: int = 60 * 60 * 24,  # 1 day in seconds
    ) -> None:
        self._entry_lifetime = datetime.timedelta(seconds=entry_lifetime)
        self._cache: dict[K, CacheEntry[V]] = {}
        self._lock = Lock()

    @classmethod
    def from_dict(cls, _dict: dict[K, V], **kw) -> Self[K, V]:
        cache = cls(**kw)
        for k, v in _dict.items():
            cache[k] = v
        return cache

    @classmethod
    def fromkeys(cls, keys: Iterator[K], v: V = None, **kw) -> Self[K, V]:
        cache = cls(**kw)
        for k in keys:
            cache[k] = v
        return cache

    # The following functions are to make the cache act like the
    #  underlying cache dictionary, they act exactly like how dictionaries do

    def keys(self) -> KeysView[K]:
        return KeysView(self)

    def __reversed__(self) -> Iterator[K]:
        yield from list(iter(self))[::-1]

    def __or__(self, other: SFDictCache | dict[K, V]) -> None:
        self_copy = copy.deepcopy(self)
        self_copy.update(other)
        return self_copy

    def __ior__(self, other: SFDictCache | dict[K, V]) -> None:
        self.update(other)

    def values(self) -> ValuesView[V]:
        return ValuesView(self)

    def items(self) -> ItemsView[K, V]:
        return ItemsView(self)

    def get(self, key: K, default: V | None = None) -> V | None:
        if key in self._cache:
            if self._is_expired(self._cache[key].expiry):
                del self._cache[key]
            else:
                return self._cache[key].entry
        return default

    def clear(self) -> None:
        self._cache.clear()

    def setdefault(self, key: K, default: V | None = None) -> V:
        return self._cache.setdefault(
            key, CacheEntry(expiry=now() + self._entry_lifetime, entry=default)
        ).entry

    def pop(self, key: K, default=None) -> V:
        # TODO: don't return expired element
        if key in self._cache:
            return self._cache.pop(key).entry
        return default

    def popitem(self) -> tuple[K, V]:
        # TODO: don't return expired element
        k, (_, v) = self._cache.popitem()
        return k, v

    def copy(self) -> Self:
        return self.__copy__()

    def __copy__(self) -> Self:
        _cache_copy = self._cache.copy()
        cache_copy = SFDictCache()
        cache_copy._cache = _cache_copy
        return cache_copy

    def __deepcopy__(self, memo: dict) -> Self:  # TODO: type-hint
        _cache_copy = copy.deepcopy(self._cache, memo=memo)
        cache_copy = SFDictCache()
        cache_copy._cache = _cache_copy
        return cache_copy

    def update(self, other: dict[K, V] | SFDictCache[K, V], **kw: dict[K, V]) -> None:
        t = now() + self._entry_lifetime
        if isinstance(other, SFDictCache):
            self._cache.update(
                {k: CacheEntry(expiry=t, entry=v) for k, v in other.items()}
            )
        elif isinstance(other, dict):
            self._cache.update(
                {k: CacheEntry(expiry=t, entry=v) for k, v in (other | kw).items()}
            )
        else:
            raise TypeError

    def __getitem__(self, k: K) -> V:
        """Returns an element if it hasn't expired yet."""
        t, v = self._cache[k]
        if self._is_expired(t):
            del self._cache[k]
            raise KeyError
        return v

    def __setitem__(self, key: K, value: V) -> None:
        self._cache[key] = CacheEntry(
            expiry=now() + self._entry_lifetime,
            entry=value,
        )

    def __delitem__(self, key: K) -> None:
        del self._cache[key]

    def __contains__(self, key: K) -> bool:
        if key in self._cache.keys():
            try:
                self[key]
                return True
            except KeyError:
                # Fall through
                pass
        return False

    def __len__(self) -> int:
        length = 0
        for _ in iter(self):
            length += 1
        return length

    def __repr__(self):
        return f"SFDictCache({len(self)})"

    def __iter__(self) -> Iterator[K]:
        for k in self._cache.keys():
            try:
                _ = self[k]
                yield k
            except KeyError:
                pass

    @staticmethod
    def _is_expired(d: datetime) -> bool:
        return now() >= d

    def _clear_expired_entries(self) -> None:
        for k, (t, _) in self._cache.items():
            if self._is_expired(t):
                del self._cache[k]
