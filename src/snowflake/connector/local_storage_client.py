#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict

from .constants import ResultStatus
from .storage_client import SnowflakeStorageClient

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent import SnowflakeFileMeta

logger = getLogger(__name__)


class SnowflakeLocalStorageClient(SnowflakeStorageClient):
    def __init__(
        self,
        meta: "SnowflakeFileMeta",
        stage_info: Dict[str, Any],
        use_s3_regional_url=False,
    ):
        super().__init__(meta, stage_info)

    def _native_download_chunk(self, chunk_id: int):
        pass

    def get_file_header(self, filename: str) -> None:
        """
        Notes:
            Checks whether the file exits in specified directory, does not return FileHeader
        """
        target_dir = os.path.join(
            os.path.expanduser(self.stage_info["location"]),
            filename,
        )
        if os.path.isfile(target_dir):
            self.meta.result_status = ResultStatus.UPLOADED
        else:
            self.meta.result_status = ResultStatus.NOT_FOUND_FILE

        return None

    def _native_upload_chunk(self, chunk_id: int):
        """
        Notes:
            Local storage ignores chunking and writes the entire file to target directory.
        """
        meta = self.meta
        logger.debug(
            f"src_file_name=[{meta.src_file_name}], real_src_file_name=[{meta.real_src_file_name}], "
            f"stage_info=[{self.stage_info}], dst_file_name=[{meta.dst_file_name}]"
        )
        if meta.src_stream is None:
            frd = open(meta.real_src_file_name, "rb")
        else:
            frd = meta.real_src_stream or meta.src_stream
        with open(
            os.path.join(
                os.path.expanduser(self.stage_info["location"]),
                meta.dst_file_name,
            ),
            "wb",
        ) as output:
            output.writelines(frd)

        if meta.src_stream is None:
            frd.close()

        meta.dst_file_size = meta.upload_size
        meta.result_status = ResultStatus.UPLOADED

    def _download_file(self, meta: "SnowflakeFileMeta") -> None:
        full_src_file_name = os.path.join(
            os.path.expanduser(self.stage_info["location"]),
            meta.src_file_name
            if not meta.src_file_name.startswith(os.sep)
            else meta.src_file_name[1:],
        )
        full_dst_file_name = os.path.join(
            meta.local_location, os.path.basename(meta.dst_file_name)
        )
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        with open(full_src_file_name, "rb") as frd:
            with open(full_dst_file_name, "wb+") as output:
                output.writelines(frd)
        statinfo = os.stat(full_dst_file_name)
        meta.dst_file_size = statinfo.st_size
        meta.result_status = ResultStatus.DOWNLOADED
