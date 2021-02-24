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

logger = getLogger(__name__)
_STAGE_NAME = "SYSTEMBIND"
_CREATE_STAGE_STMT = f"create temporary stage {_STAGE_NAME} file_format=(type=csv field_optionally_enclosed_by='\"')"


class BindException(Exception):
    pass


class BindUploadAgent:

    def __init__(self, cursor: 'SnowflakeCursor', rows: List[bytes], stream_buffer_size: int = 1024 * 1024 * 10):
        """Construct an agent that uploads binding parameters as CSV files to a temporary stage.

        Args:
            cursor: The cursor object.
            rows: Rows of binding parameters in CSV format.
            stream_buffer_size: Size of each file, default to 10MB.
        """
        self.cursor = cursor
        self.rows = rows
        self._stream_buffer_size = stream_buffer_size
        self.stage_path = f"@{_STAGE_NAME}/{uuid.uuid4().hex}"

    def _create_stage(self):
        self.cursor.execute(_CREATE_STAGE_STMT)

    def upload(self):
        try:
            self._create_stage()
        except Exception as exc:
            logger.debug("Failed to create stage for binding.")
            self.cursor.connection._session_parameters['CLIENT_STAGE_ARRAY_BINDING_THRESHOLD'] = 0
            raise BindException() from exc

        row_idx = 0
        while row_idx < len(self.rows):
            f = BytesIO()
            size = 0
            while row_idx < len(self.rows) and size + len(self.rows[row_idx]) <= self._stream_buffer_size:
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
