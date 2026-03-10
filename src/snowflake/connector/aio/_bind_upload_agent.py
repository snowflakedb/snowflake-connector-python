#!/usr/bin/env python


from __future__ import annotations

import os
from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, cast

from snowflake.connector import Error
from snowflake.connector._utils import get_temp_type_for_object
from snowflake.connector.bind_upload_agent import BindUploadAgent as BindUploadAgentSync
from snowflake.connector.errors import BindUploadError

if TYPE_CHECKING:
    from snowflake.connector.aio import SnowflakeCursor

logger = getLogger(__name__)


class BindUploadAgent(BindUploadAgentSync):
    def __init__(
        self,
        cursor: SnowflakeCursor,
        rows: list[bytes],
        stream_buffer_size: int = 1024 * 1024 * 10,
    ) -> None:
        super().__init__(cursor, rows, stream_buffer_size)
        self.cursor = cast("SnowflakeCursor", cursor)

    async def _create_stage(self) -> None:
        create_stage_sql = (
            f"create or replace {get_temp_type_for_object(self._use_scoped_temp_object)} stage {self._STAGE_NAME} "
            "file_format=(type=csv field_optionally_enclosed_by='\"')"
        )
        await self.cursor.execute(create_stage_sql)

    async def upload(self) -> None:
        try:
            await self._create_stage()
        except Error as err:
            self.cursor.connection._session_parameters[
                "CLIENT_STAGE_ARRAY_BINDING_THRESHOLD"
            ] = 0
            logger.debug("Failed to create stage for binding.")
            raise BindUploadError from err

        row_idx = 0
        while row_idx < len(self.rows):
            f = BytesIO()
            size = 0
            while True:
                f.write(self.rows[row_idx])
                size += len(self.rows[row_idx])
                row_idx += 1
                if row_idx >= len(self.rows) or size >= self._stream_buffer_size:
                    break
            try:
                f.seek(0)
                await self.cursor._upload_stream(
                    input_stream=f,
                    stage_location=os.path.join(self.stage_path, f"{row_idx}.csv"),
                    options={"source_compression": "auto_detect"},
                )
            except Error as err:
                logger.debug("Failed to upload the bindings file to stage.")
                raise BindUploadError from err
            f.close()
