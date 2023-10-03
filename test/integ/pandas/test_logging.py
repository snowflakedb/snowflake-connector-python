#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging


def test_rand_table_log(caplog, conn_cnx, db_parameters):
    with conn_cnx() as conn:
        caplog.set_level(logging.DEBUG, "snowflake.connector")

        num_of_rows = 10
        with conn.cursor() as cur:
            cur.execute(
                "select randstr(abs(mod(random(), 100)), random()) from table(generator(rowcount => {}));".format(
                    num_of_rows
                )
            ).fetchall()

        # make assertions
        has_batch_read = has_batch_size = has_chunk_info = has_batch_index = False
        for record in caplog.records:
            if "Batches read:" in record.msg:
                has_batch_read = True
                assert "arrow_iterator" in record.filename
                assert "__cinit__" in record.funcName

            if "Arrow BatchSize:" in record.msg:
                has_batch_size = True
                assert "CArrowIterator.cpp" in record.filename
                assert "CArrowIterator" in record.funcName

            if "Arrow chunk info:" in record.msg:
                has_chunk_info = True
                assert "CArrowChunkIterator.cpp" in record.filename
                assert "CArrowChunkIterator" in record.funcName

            if "Current batch index:" in record.msg:
                has_batch_index = True
                assert "CArrowChunkIterator.cpp" in record.filename
                assert "next" in record.funcName

        # each of these records appear at least once in records
        assert has_batch_read and has_batch_size and has_chunk_info and has_batch_index
