#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import datetime

import pytest

try:
    import snowflake.connector.cache as cache
except ImportError:
    cache = None

# Used to insert entries that expire instantaneously
NO_LIFETIME = datetime.timedelta(seconds=0)


class TestSFDictCache:
    def test_simple_usage(self):
        c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
        assert 1 in c and 2 in c
        assert c[1] == "a"
        assert c[2] == "b"

    def test_expiration(self):
        c = cache.SFDictCache.from_dict(
            {"a": 1},
            entry_lifetime=0,
        )
        with pytest.raises(KeyError):
            c[1]

    def test_access_empty(self):
        c = cache.SFDictCache()
        with pytest.raises(KeyError):
            c[1]

    # The rest of tests test that SFDictCache acts like a regular dictionary.

    def test_cast_list(self):
        c = cache.SFDictCache.from_dict({"a": 1, "b": 2})
        assert list(c) == ["a", "b"]

    def test_access(self):
        c = cache.SFDictCache.from_dict({"a": 1})
        assert c["a"] == 1
        c._entry_lifetime = NO_LIFETIME
        c["b"] = 2
        with pytest.raises(KeyError):
            c["b"]

    def test_delete(self):
        c = cache.SFDictCache.from_dict({"a": 1})
        del c["a"]
        assert len(c.keys()) == 0

    def test_contains(self):
        c = cache.SFDictCache.from_dict({"a": 1})
        assert "a" in c
        c._entry_lifetime = NO_LIFETIME
        c["b"] = 2
        assert "b" not in c
        assert "c" not in c

    def test_iter(self):
        c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
        counter = 1
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["a"] = 100
        for e in iter(c):
            assert e == counter
            # Make sure that cache can be modified while iterating
            del c[e]
            counter += 1
        assert len(c._cache) == 0

    def test_clear(self):
        c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
        assert len(c.keys()) == 2
        c.clear()
        assert len(c.keys()) == 0

    def test_get(self):
        c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
        assert c.get("a", -999) == -999
        assert c.get(1) == "a"
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["d"] = 4
        assert c.get("d") is None

    def test_items(self):
        c = cache.SFDictCache()
        assert c.items() == []
        c["a"] = 1
        c["b"] = 2
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["c"] = 3
        assert c.items() == [("a", 1), ("b", 2)]

    def test_keys(self):
        c = cache.SFDictCache()
        assert list(c.keys()) == []
        c["a"] = 1
        c["b"] = 2
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["c"] = 3
        assert c.keys() == ["a", "b"]

    def test_update(self):
        c = cache.SFDictCache()
        c.update({"a": 1, "b": 2})
        c.update(cache.SFDictCache.from_dict({"c": 3}))
        assert c.items() == [("a", 1), ("b", 2), ("c", 3)]
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["d"] = 4
        assert c.items() == [("a", 1), ("b", 2), ("c", 3)]

    def test_values(self):
        c = cache.SFDictCache()
        assert c.values() == []
        c["a"] = 1
        c["b"] = 2
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["c"] = 3
        assert c.values() == [1, 2]

    def test_telemetry(self):
        c = cache.SFDictCache.from_dict({"a": 1, "b": 2})
        assert c.telemetry == {
            "hit": 0,
            "miss": 0,
            "expiration": 0,
            "size": 2,
        }
        c["a"] = 1
        assert c.telemetry["hit"] == 0
        assert c["a"] == 1
        assert c.telemetry["hit"] == 1
        with pytest.raises(KeyError):
            c["c"]
        assert c.telemetry["miss"] == 1
        # Make sure that this filters out expired entries
        c._entry_lifetime = NO_LIFETIME
        c["c"] = 3
        with pytest.raises(KeyError):
            c["c"]
        assert c.telemetry["expiration"] == 1
        assert c.get("c") is None
        assert c.telemetry["miss"] == 2
        # These functions should not affect any numbers other than expirations
        c["c"] = 3  # expired
        assert c.values() == [1, 2]
        assert c.keys() == ["a", "b"]
        assert c.items() == [("a", 1), ("b", 2)]
        assert c.telemetry == {
            "hit": 1,
            "miss": 2,
            "expiration": 2,
            "size": 2,
        }
        assert "b" in c
        c.clear()
        assert c.telemetry == {
            "hit": 0,
            "miss": 0,
            "expiration": 0,
            "size": 0,
        }
        c.update({"a": 1, "b": 2})
        assert c.telemetry == {
            "hit": 0,
            "miss": 0,
            "expiration": 0,
            "size": 2,
        }
