#!/usr/bin/env python

#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import uuid
from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover
    from .cursor import SnowflakeCursor

stream_buffer_size = 1024 * 1024 * 10  # 10 MB default
STAGE_NAME = "SYSTEMBIND"
CREATE_STAGE_STMT = f"create temporary stage {STAGE_NAME} file_format=(type=csv field_optionally_enclosed_by='\"')"
logger = getLogger(__name__)


class BindException(Exception):
    pass


class BindUploadAgent:
    def __init__(self, cursor: 'SnowflakeCursor', rows: List[bytes]):
        self.cursor = cursor
        self.rows = rows
        self.stage_path = f"@{STAGE_NAME}/{uuid.uuid4().hex}"

    def _create_stage(self):
        self.cursor.execute(CREATE_STAGE_STMT)

    def upload(self):
        try:
            self._create_stage()
        except Exception as exc:
            self.cursor.connection._session_parameters['CLIENT_STAGE_ARRAY_BINDING_THRESHOLD'] = float('inf')
            logger.debug("Failed to create stage for binding, disabled client stage array binding.")
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
                self.cursor.execute(f"PUT file://{row_idx}.csv {self.stage_path}", file_stream=f)
            except Exception as exc:
                logger.debug("Failed to upload the bindings file to stage.")
                raise BindException from exc
            if not f.closed:
                f.close()
