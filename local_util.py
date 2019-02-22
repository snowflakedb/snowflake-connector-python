#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
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
            u"src_file_name=[%s], "
            u"real_src_file_name=[%s], "
            u"stage_info=[%s], "
            u"dst_file_name=[%s]",
            meta[u'src_file_name'],
            meta[u'real_src_file_name'],
            meta[u'stage_info'],
            meta[u'dst_file_name']
        )
        with open(meta[u'real_src_file_name'], u'rb') as frd:
            with open(os.path.join(
                    os.path.expanduser(meta[u'stage_info'][u'location']),
                    meta[u'dst_file_name']), u'wb') as output:
                output.writelines(frd)

        meta[u'dst_file_size'] = meta[u'upload_size']
        meta[u'result_status'] = ResultStatus.UPLOADED

    @staticmethod
    def download_one_file(meta):
        full_src_file_name = os.path.join(
            os.path.expanduser(meta[u'stage_info'][u'location']),
            meta[u'src_file_name'] if not meta[u'src_file_name'].startswith(
                os.sep) else
            meta[u'src_file_name'][1:])
        full_dst_file_name = os.path.join(
            meta[u'local_location'],
            os.path.basename(meta[u'dst_file_name']))
        base_dir = os.path.dirname(full_dst_file_name)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        with open(full_src_file_name, u'rb') as frd:
            with open(full_dst_file_name, u'wb+') as output:
                output.writelines(frd)
        statinfo = os.stat(full_dst_file_name)
        meta[u'dst_file_size'] = statinfo.st_size
        meta[u'result_status'] = ResultStatus.DOWNLOADED
