import logging
import math

logger = logging.getLogger(__name__)

CURRENT_CHUNK_SIZE = 8388608
MAX_OBJECT_SIZE = 5497558138880
MAX_PART_SIZE = 5368709120
MIN_PART_SIZE = 5242880
MAX_PARTS = 10000

class computeChunkSize:
    def __init__(
        self,
        current_chunk_size = CURRENT_CHUNK_SIZE,
        max_object_size = MAX_OBJECT_SIZE,
        max_part_size = MAX_PART_SIZE,
        min_part_size = MIN_PART_SIZE,
        max_parts = MAX_PARTS):

        self.current_chunk_size = current_chunk_size
        self.max_object_size = max_object_size
        self.max_part_size = max_part_size
        self.min_part_size = min_part_size
        self.max_parts= max_parts

    def compute_chunk_size(self, file_size=None):
        
        chunk_size = self.current_chunk_size

        # check if we don't exceed the allowed max file size 5 TiB
        if file_size is not None and file_size < self.max_object_size:
            chunk_size = self._compute_max_parts(chunk_size, file_size)
        
        else:
            logger.error(
                "File size %s exceeds the maximum file size %s." % (file_size, self.max_object_size)
            )

        return self._compute_min_chunk_size(chunk_size)

    # check lower chunk size limit 5 MiB
    def _compute_min_chunk_size(self, current_chunk_size):
        chunk_size = current_chunk_size

        if chunk_size < self.min_part_size:
            logger.debug(
                "Setting chunksize to %s instead of the default %s." 
                % (self.current_chunk_size, current_chunk_size)
            )
            return self.min_part_size
        else:
            return current_chunk_size

    # check lower chunk size limit 
    def _compute_max_parts(self, current_chunk_size, file_size):
        chunk_size = current_chunk_size
        num_parts = int(math.ceil(file_size / float(current_chunk_size)))

        if num_parts > self.max_parts:
            chunk_size = int(math.ceil(file_size / float(self.max_parts)))

        if chunk_size != current_chunk_size:

            logger.debug(
                "Setting chunksize to %s instead of the default %s." 
                % (chunk_size, current_chunk_size)
                )

        return chunk_size