#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
from logging import getLogger
from typing import TYPE_CHECKING, Any, Dict

from .constants import DEFAULT_S3_CONNECTION_POOL_SIZE, ResultStatus

if TYPE_CHECKING:  # pragma: no cover
    from .file_transfer_agent_sdk import SnowflakeFileMeta


class SnowflakeLocalUtil(object):
    @staticmethod
    def create_client(
        stage_info: Dict[str, Any],
        use_accelerate_endpoint: bool = False,
        use_s3_regional_url: bool = False,
        s3_connection_pool_size: int = DEFAULT_S3_CONNECTION_POOL_SIZE,
    ):
        return None

    @staticmethod
    def upload_one_file_with_retry(meta: "SnowflakeFileMeta") -> None:
        logger = getLogger(__name__)
        logger.debug(
            f"src_file_name=[{meta.src_file_name}], real_src_file_name=[{meta.real_src_file_name}], "
            f"stage_info=[{meta.client_meta.stage_info}], dst_file_name=[{meta.dst_file_name}]"
        )
        frd = None
        if meta.src_stream is None:
            frd = open(meta.real_src_file_name, "rb")
        else:
            frd = meta.real_src_stream or meta.src_stream
        with open(
            os.path.join(
                os.path.expanduser(meta.client_meta.stage_info["location"]),
                meta.dst_file_name,
            ),
            "wb",
        ) as output:
            output.writelines(frd)

        meta.dst_file_size = meta.upload_size
        meta.result_status = ResultStatus.UPLOADED

    @staticmethod
    def download_one_file(meta: "SnowflakeFileMeta") -> None:
        full_src_file_name = os.path.join(
            os.path.expanduser(meta.client_meta.stage_info["location"]),
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
