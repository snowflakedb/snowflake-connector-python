#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import os
import sys

import snowflake.connector.cache as cache

tmpdir = sys.argv[1]

cache_path = os.path.join(tmpdir, "cache.txt")
assert os.listdir(tmpdir) == []
c1 = cache.SFDictFileCache(file_path=cache_path)
c1["key"] = "value"
c1._save()
assert os.listdir(tmpdir) == ["cache.txt", "cache.txt.lock"]
