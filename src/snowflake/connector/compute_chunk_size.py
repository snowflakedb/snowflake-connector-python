#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import math

from .constants import (
    S3_DEFAULT_CHUNK_SIZE,
    S3_MAX_OBJECT_SIZE,
    S3_MAX_PARTS,
    S3_MIN_PART_SIZE,
)
from .errors import Error

logger = logging.getLogger(__name__)


def chunk_size_calculator(file_size: int) -> int:
    default_chunk_size = S3_DEFAULT_CHUNK_SIZE
    max_object_size = S3_MAX_OBJECT_SIZE
    min_part_size = S3_MIN_PART_SIZE
    max_parts = S3_MAX_PARTS
    calculated_chunk_size = 0

    # check if we don't exceed the allowed S3 max file size 5 TiB
    if file_size is not None and file_size > max_object_size:
        num_parts = math.ceil(file_size / default_chunk_size)

        if num_parts > max_parts:
            calculated_chunk_size = math.ceil(file_size / max_parts)

        if calculated_chunk_size < min_part_size:
            logger.debug(
                f"Setting chunksize to {min_part_size} instead of the default {default_chunk_size}."
            )
            calculated_chunk_size = min_part_size

        if calculated_chunk_size != default_chunk_size:
            logger.debug(
                f"Setting chunksize to {calculated_chunk_size} instead of the default {default_chunk_size}."
            )
    else:
        error_message = (
            f"File size {file_size} exceeds the maximum file size {max_object_size}."
        )
        logger.error(error_message)
        raise Error(error_message)

    return calculated_chunk_size
