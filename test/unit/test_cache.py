#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import copy
import datetime

import pytest

import snowflake.connector.cache as cache

# Used to insert entries that expire instantaneously
NO_LIFETIME = datetime.timedelta(seconds=0)


def test_simple_usage():
    c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
    assert 1 in c and 2 in c


def test_expiration():
    c = cache.SFDictCache.from_dict({1: "a"}, entry_lifetime=0)
    with pytest.raises(KeyError):
        c[1]


def test_access_empty():
    c = cache.SFDictCache()
    with pytest.raises(KeyError):
        c[1]


# The rest of tests test that SFDictCache acts like a regular dictionary.


def test_cast_list():
    c = cache.SFDictCache.from_dict({"a": 1, "b": 2})
    assert list(c) == ["a", "b"]


def test_len():
    c = cache.SFDictCache.from_dict({"a": 1, "b": 2, "c": 3})
    assert len(c) == 3
    c["d"] = 4
    assert len(c) == 4


def test_len_cleanup():
    c = cache.SFDictCache.from_dict(
        {"a": 1, "b": 2, "c": 3},
        entry_lifetime=0,
    )
    # Make sure original items were inserted
    assert len(c._cache) == 3
    assert len(c) == 0


def test_access():
    c = cache.SFDictCache.from_dict({"a": 1})
    assert c["a"] == 1
    c._entry_lifetime = NO_LIFETIME
    c["b"] = 2
    with pytest.raises(KeyError):
        c["b"]


def test_delete():
    c = cache.SFDictCache.from_dict({"a": 1})
    del c["a"]
    assert len(c) == 0


def test_contains():
    c = cache.SFDictCache.from_dict({"a": 1})
    assert "a" in c
    c._entry_lifetime = NO_LIFETIME
    c["b"] = 2
    assert "b" not in c
    assert "c" not in c


def test_iter():
    c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
    counter = 1
    for e in iter(c):
        assert e == counter
        counter += 1


def test_clear():
    c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
    assert len(c) == 2
    c.clear()
    assert len(c) == 0


def test_copies():
    c = cache.SFDictCache.from_dict(
        {
            2: [
                "b",
            ]
        }
    )
    c2 = c.copy()
    assert list(c.values()) == list(c2.values())
    assert c is not c2
    c3 = copy.copy(c)
    assert list(c.values()) == list(c3.values())
    assert c is not c3
    c4 = copy.deepcopy(c)
    assert list(c.values()) == list(c4.values())
    assert c is not c4
    c[2].append("c")
    assert c[2] == c2[2] == c3[2]
    assert c[2] != c4[2]
    assert 3 not in c4


def test_from_keys():
    c = cache.SFDictCache.fromkeys(("a", "b"), 999)
    assert list(c.items()) == [("a", 999), ("b", 999)]


def test_get():
    c = cache.SFDictCache.from_dict({1: "a", 2: "b"})
    assert c.get("a", -999) == -999
    assert c.get(1) == "a"


def test_items():
    c = cache.SFDictCache()
    i = c.items()
    assert list(i) == []
    c["a"] = 1
    c["b"] = 2
    # Make sure that this filters out expired entries
    c._entry_lifetime = NO_LIFETIME
    c["c"] = 3
    assert list(i) == [("a", 1), ("b", 2)]


def test_keys():
    c = cache.SFDictCache()
    k = c.keys()
    assert list(k) == []
    c["a"] = 1
    c["b"] = 2
    # Make sure that this filters out expired entries
    c._entry_lifetime = NO_LIFETIME
    c["c"] = 3
    assert list(k) == ["a", "b"]


def test_pop():
    c = cache.SFDictCache.from_dict({"a": 1, "b": 2, "c": 3})
    assert c.pop("a") == 1
    assert c.pop("d", -1) == -1
    assert c.pop("d") is None
    assert list(c.items()) == [("b", 2), ("c", 3)]


def test_popitem():
    c = cache.SFDictCache.from_dict({"a": 1, "b": 2, "c": 3})
    assert c.popitem() == ("c", 3)
    assert list(c.items()) == [("a", 1), ("b", 2)]


def test_reversed():
    c = cache.SFDictCache.from_dict({"a": 1, "b": 2, "c": 3})
    assert list(reversed(c)) == ["c", "b", "a"]


def test_setdefault():
    c = cache.SFDictCache()
    assert c.setdefault("a", 1) == 1
    assert c["a"] == 1


def test_update():
    c = cache.SFDictCache()
    c.update({"a": 1, "b": 2})
    c.update(cache.SFDictCache.from_dict({"c": 3}))
    assert list(c.items()) == [("a", 1), ("b", 2), ("c", 3)]


def test_values():
    c = cache.SFDictCache()
    v = c.values()
    assert list(v) == []
    c["a"] = 1
    c["b"] = 2
    # Make sure that this filters out expired entries
    c._entry_lifetime = NO_LIFETIME
    c["c"] = 3
    assert list(v) == [1, 2]


def test_operatorpipe():
    c = cache.SFDictCache.from_dict({"a": 1}) | cache.SFDictCache.from_dict(
        {"b": 2} | {"c": 3}
    )
    assert list(c.items()) == [("a", 1), ("b", 2), ("c", 3)]
