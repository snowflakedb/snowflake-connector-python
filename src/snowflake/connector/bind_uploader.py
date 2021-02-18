#!/usr/bin/env python

#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import uuid
from io import BytesIO
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover
    from .cursor import SnowflakeCursor

stream_buffer_size = 1024 * 1024 * 10  # 10 MB default
STAGE_NAME = "SYSTEM$BIND"
CREATE_STAGE_STMT = f"create temporary stage {STAGE_NAME} file_format=(type=csv field_optionally_enclosed_by='\"')"


class BindException(Exception):
    pass


class BindUploadAgent:
    def __init__(self, cursor: 'SnowflakeCursor', rows: List[bytes]):
        self.cursor = cursor
        self.rows = rows
        self.stage_path = f"@{STAGE_NAME}/{uuid.uuid4()}"

    def upload(self):
        try:
            self.cursor.execute(CREATE_STAGE_STMT)
        except Exception as exc:
            # TBD: find out specific exception for permission denied
            self.connection._session_parameters['CLIENT_STAGE_ARRAY_BINDING_THRESHOLD'] = float('inf')
            raise BindException from exc

        row_idx = 0
        while row_idx < len(self.rows):
            f = BytesIO()
            size = 0
            while row_idx < len(self.rows) and size + len(self.rows[row_idx]) <= stream_buffer_size:
                f.write(self.rows[row_idx])
                size += len(self.rows[row_idx])
                row_idx += 1
            try:
                self.cursor.execute(f"PUT file://{row_idx}.csv {self.stage_path}")
            except Exception as exc:
                raise BindException from exc
            if not f.closed:
                f.close()
