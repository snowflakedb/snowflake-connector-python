#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
import os
import pathlib
import platform
import subprocess
import sys

import snowflake.connector.ocsp_snowflake

# This script run every Python file in this directory other than this
#  one in a subprocess and checks their exit codes


file_ignore_list = ["run.py", "__init__.py"]

for test_file in pathlib.Path(__file__).parent.glob("*.py"):
    if test_file.name not in file_ignore_list:
        print(f"Running {test_file}")
        sub_process = subprocess.run(
            [
                sys.executable if sys.executable else "python",
                "-m",
                f"test.extras.{test_file.name[:-3]}",
            ]
        )
        sub_process.check_returncode()
        ocsp_cache_dir_path = pathlib.Path(
            snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE.file_path
        ).parent
        cache_files = set(os.listdir(ocsp_cache_dir_path))
        # This is to test SNOW-79940, making sure tmp files are removed
        # Windows does not have ocsp_response_validation_cache.lock
        assert (
            cache_files
            == {
                "ocsp_response_validation_cache.lock",
                "ocsp_response_validation_cache",
                "ocsp_response_cache.json",
            }
            and not platform.system() == "Windows"
        ) or (
            cache_files
            == {
                "ocsp_response_validation_cache",
                "ocsp_response_cache.json",
            }
            and platform.system() == "Windows"
        )
