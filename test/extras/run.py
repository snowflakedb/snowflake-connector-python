#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pathlib
import subprocess
import sys

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
