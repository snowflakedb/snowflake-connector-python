#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
import pickle


def test_pickle_timestamp_tz(tmpdir, conn_cnx):
    """Ensures the timestamp_tz result is pickle-able."""
    tmp_dir = str(tmpdir.mkdir("pickles"))
    output = os.path.join(tmp_dir, "tz.pickle")
    expected_tz = None
    with conn_cnx() as con:
        for rec in con.cursor().execute(
            "select '2019-08-11 01:02:03.123 -03:00'::TIMESTAMP_TZ"
        ):
            expected_tz = rec[0]
            with open(output, "wb") as f:
                pickle.dump(expected_tz, f)

    with open(output, "rb") as f:
        read_tz = pickle.load(f)
        assert expected_tz == read_tz
