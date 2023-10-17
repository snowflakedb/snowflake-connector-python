import logging
import math

logger = logging.getLogger(__name__)

constants = {
    "CURRENT_CHUNK_SIZE" : 8388608,
    "MAX_OBJECT_SIZE" : 5497558138880,
    "MAX_PART_SIZE" : 5368709120,
    "MIN_PART_SIZE" : 5242880,
    "MAX_PARTS" : 10000
}

class ChunkSizeCalculator:
    def __init__(
        self,
        current_chunk_size: int = constants["CURRENT_CHUNK_SIZE"],
        max_object_size: int = constants["MAX_OBJECT_SIZE"],
        max_part_size: int = constants["MAX_PART_SIZE"],
        min_part_size: int = constants["MIN_PART_SIZE"],
        max_parts: int = constants["MAX_PARTS"]
        ) -> None :

        self.current_chunk_size = current_chunk_size
        self.max_object_size = max_object_size
        self.max_part_size = max_part_size
        self.min_part_size = min_part_size
        self.max_parts= max_parts

    def compute_chunk_size(self, file_size: int = None) -> int:
        
        chunk_size = self.current_chunk_size

        # check if we don"t exceed the allowed max file size 5 TiB
        if file_size is not None and file_size < self.max_object_size:
            chunk_size = self._check_max_parts(chunk_size, file_size)
        
        else:
            error_message = f"File size %s exceeds the maximum file size %s.".format(file_size, self.max_object_size)
            logger.error(error_message)
            raise Exception(error_message)

        return self._check_min_chunk_size(chunk_size)

    # check lower chunk size limit 5 MiB
    def _check_min_chunk_size(self, current_chunk_size: int) -> int:
        chunk_size = current_chunk_size

        if chunk_size < self.min_part_size:
            logger.debug(
                "Setting chunksize to %s instead of the default %s." 
                % (self.current_chunk_size, current_chunk_size)
            )
            return self.min_part_size
        else:
            return current_chunk_size

    # check max chunks number 10k  
    def _check_max_parts(self, current_chunk_size: int, file_size: int) -> int:
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