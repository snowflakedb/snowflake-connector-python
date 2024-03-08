#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
import os
import tempfile
from io import BufferedReader, BufferedWriter
from logging import getLogger
from math import ceil
from typing import Any

from .constants import FileHeader, ResultStatus
from .file_util import SnowflakeFileUtil
from .storage_client import SnowflakeStorageClient
from .vendored import requests

logger = getLogger(__name__)
# Default gRPC message size is 4 MB
GRPC_CHUNK_SIZE = os.getenv("PYTHON_SP_PUT_GET_CHUNK_SIZE", 4 * 1024 * 1024)


class StoredProcStorageClient(SnowflakeStorageClient):
    def __init__(
        self,
        meta: SnowflakeFileMeta,
        stage_info: dict[str, Any],
    ) -> None:
        super().__init__(meta, stage_info, chunk_size=0, chunked_transfer=False)
        self.meta = meta
        self.tmp_dir = tempfile.mkdtemp(dir="/tmp")
        self.data_file: str | None = None

        # UPLOAD
        meta.real_src_file_name = meta.src_file_name
        meta.upload_size = meta.src_file_size
        self.preprocessed = (
            False  # so we don't repeat compression/file digest when re-encrypting
        )
        # DOWNLOAD
        self.full_dst_file_name: str | None = (
            os.path.realpath(
                os.path.join(
                    self.meta.local_location, os.path.basename(self.meta.dst_file_name)
                )
            )
            if self.meta.local_location
            else None
        )

    def compress(self) -> None:
        if self.meta.require_compress:
            meta = self.meta
            logger.debug(f"compressing file={meta.src_file_name}")
            if meta.intermediate_stream:
                (
                    meta.src_stream,
                    upload_size,
                ) = SnowflakeFileUtil.compress_with_gzip_from_stream(
                    meta.intermediate_stream
                )
            else:
                (
                    meta.real_src_file_name,
                    upload_size,
                ) = SnowflakeFileUtil.compress_file_with_gzip(
                    meta.src_file_name, self.tmp_dir
                )

    def file_exists(self, filename):
        try:
            import _sfstream

            with _sfstream.SfStream(
                self.stage_info["location"] + filename,
                file_type=_sfstream.FileType.STAGE,
                mode=_sfstream.Mode.READ,
                rso_id=int(os.environ.get("SNOWFLAKE_RSO_ID", -1)),
            ):
                return True
        except SystemError as e:
            if (
                e.__cause__ is not None
                and "File does not exist or not authorized" in str(e.__cause__)
            ):
                return False
            raise e.__cause__

    def get_file_header(self, filename: str):
        # TODO: need a faster way to get the digest of the file inside stored proc. Skip it for now

        if self.file_exists(filename):
            self.meta.result_status = ResultStatus.UPLOADED
            return FileHeader(None, None, None)
        else:
            self.meta.result_status = ResultStatus.NOT_FOUND_FILE
            return None

    def _upload_chunk(self, chunk_id: int, chunk: bytes) -> None:
        import _sfstream

        dest_path = self.stage_info["location"] + self.meta.dst_file_name
        wstream = _sfstream.SfStream(
            dest_path,
            file_type=_sfstream.FileType.STAGE,
            mode=_sfstream.Mode.WRITE,
            rso_id=int(os.environ.get("SNOWFLAKE_RSO_ID", -1)),
        )
        writer = BufferedWriter(wstream)

        for grpc_chunk_id in range(0, ceil(len(chunk) / GRPC_CHUNK_SIZE)):
            content = chunk[
                grpc_chunk_id * GRPC_CHUNK_SIZE : (grpc_chunk_id + 1) * GRPC_CHUNK_SIZE
            ]
            writer.write(content)

        writer.close()

        self.meta.upload_size = wstream.padded_file_size

    def download_chunk(self, chunk_id: int) -> None:
        import _sfstream

        rstream = _sfstream.SfStream(
            self.stage_info["location"] + self.meta.src_file_name,
            file_type=_sfstream.FileType.STAGE,
            mode=_sfstream.Mode.READ,
            rso_id=int(os.environ.get("SNOWFLAKE_RSO_ID", -1)),
        )
        reader = BufferedReader(rstream)

        with open(self.intermediate_dst_path, "wb") as sfd:
            # SfStream internally handles chunk reads
            sfd.write(reader.read())

        reader.close()

    def _has_expired_token(self, response: requests.Response) -> bool:
        return False
