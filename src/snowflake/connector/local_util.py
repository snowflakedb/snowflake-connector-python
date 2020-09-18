#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

from __future__ import division

import os
from logging import getLogger

from .constants import ResultStatus


class SnowflakeLocalUtil(object):
    @staticmethod
    def create_client(stage_info, use_accelerate_endpoint=False):
        return None

    @staticmethod
    def upload_one_file_with_retry(meta):
        logger = getLogger(__name__)
        logger.debug(
            "src_file_name=[%s], "
            "real_src_file_name=[%s], "
            "stage_info=[%s], "
            "dst_file_name=[%s]",
            meta['src_file_name'],
            meta['real_src_file_name'],
            meta['stage_info'],
            meta['dst_file_name']
        )
        with open(meta['real_src_file_name'], 'rb') as frd:
            with open(os.path.join(
                    os.path.expanduser(meta['stage_info']['location']),
                    meta['dst_file_name']), 'wb') as output:
                output.writelines(frd)

        meta['dst_file_size'] = meta['upload_size']
        meta['result_status'] = ResultStatus.UPLOADED

    @staticmethod
    def download_one_file(meta):
        full_src_file_name = os.path.join(
            os.path.expanduser(meta['stage_info']['location']),
            meta['src_file_name'] if not meta['src_file_name'].startswith(
                os.sep) else
            meta['src_file_name'][1:])
        full_dst_file_name = os.path.join(
            meta['local_location'],
            os.path.basename(meta['dst_file_name']))
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        with open(full_src_file_name, 'rb') as frd:
            with open(full_dst_file_name, 'wb+') as output:
                output.writelines(frd)
        statinfo = os.stat(full_dst_file_name)
        meta['dst_file_size'] = statinfo.st_size
        meta['result_status'] = ResultStatus.DOWNLOADED
