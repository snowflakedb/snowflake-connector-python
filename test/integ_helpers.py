#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os


def put(csr, file_path, stage_path, from_path, sql_options="", **kwargs):
    sql = "put 'file://{file}' @{stage} {sql_options}"
    if from_path:
        kwargs.pop('file_stream', None)
    else:
        # PUT from stream
        file_path = os.path.basename(file_path)
    if kwargs.pop('commented', False):
        sql = '--- test comments\n' + sql
    sql = sql.format(file=file_path.replace('\\', '\\\\'),
                     stage=stage_path,
                     sql_options=sql_options)
    return csr.execute(sql, **kwargs)
