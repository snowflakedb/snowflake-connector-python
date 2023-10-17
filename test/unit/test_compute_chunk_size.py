from snowflake.connector.compute_chunk_size import ChunkSizeCalculator, constants

import unittest

class test_ChunkSizeCalculator(unittest.TestCase):

    def setUp(self):
        self.chunk_size_calculator = ChunkSizeCalculator()
        self.expected_chunk_size = constants["CURRENT_CHUNK_SIZE"]
        self.max_part_size = constants["MAX_PART_SIZE"]
        self.min_part_size = constants["MIN_PART_SIZE"]
        self.max_object_size = constants["MAX_OBJECT_SIZE"]
        self.sample_file_size_2gb = 2 * 1024 * 1024 * 1024
        self.sample_file_size_85gb = 85 * 1024 * 1024 * 1024
        self.sample_file_size_2gb = 2 * 1024 * 1024 * 1024
        self.sample_file_size_5tb = 4.9 * 1024 * 1024 * 1024 * 1024
        self.sample_file_size_6tb = 6 * 1024 * 1024 * 1024 * 1024
        self.sample_chunk_size_4mb = 4 * 1024 * 1024
        self.sample_chunk_size_10mb = 10 * 1024 * 1024

    def tearDown(self):
        pass

    def test_check_chunk_size(self):
        chunk_size_1 = self.chunk_size_calculator.compute_chunk_size(self.sample_file_size_2gb)
        self.assertEqual(chunk_size_1, self.expected_chunk_size)

        chunk_size_2 = self.chunk_size_calculator.compute_chunk_size(self.sample_file_size_5tb)
        self.assertLessEqual(chunk_size_2, self.max_part_size)
        
        error_message = f"File size {self.sample_file_size_6tb} exceeds the maximum file size {self.max_object_size}."

        with self.assertRaises(Exception) as context:
            self.chunk_size_calculator(self.sample_file_size_6tb)
            self.assertEqual(context.exception.message, error_message)

    def test_check_min_chunk_size(self):
        chunk_size_1 = self.chunk_size_calculator._check_min_chunk_size(self.sample_chunk_size_4mb)
        self.assertEqual(chunk_size_1, self.min_part_size)

        chunk_size_2 = self.chunk_size_calculator._check_min_chunk_size(self.sample_chunk_size_10mb)
        self.assertEqual(chunk_size_2, self.sample_chunk_size_10mb)

    def test_check_max_parts(self):
        chunk_size_3 = self.chunk_size_calculator._check_max_parts(self.expected_chunk_size, self.sample_file_size_85gb)
        self.assertLessEqual(chunk_size_3, self.max_part_size)
        self.assertGreaterEqual(chunk_size_3, self.min_part_size)

        chunk_size_4 = self.chunk_size_calculator._check_max_parts(self.expected_chunk_size, self.sample_file_size_2gb)
        self.assertLessEqual(chunk_size_4, self.max_part_size)
        self.assertGreaterEqual(chunk_size_4, self.min_part_size)
