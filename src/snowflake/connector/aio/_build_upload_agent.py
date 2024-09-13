#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, cast

from snowflake.connector import Error
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
        await self.cursor.execute(self._CREATE_STAGE_STMT)

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
                await self.cursor.execute(
                    f"PUT file://{row_idx}.csv {self.stage_path}", file_stream=f
                )
            except Error as err:
                logger.debug("Failed to upload the bindings file to stage.")
                raise BindUploadError from err
            f.close()
