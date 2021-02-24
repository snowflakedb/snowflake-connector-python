#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

# This script run every Python file in this directory other than this one in a subprocess
# and checks their exit codes

import pathlib
import subprocess
import sys

file_ignore_list = ["run.py", "__init__.py"]

for test_file in pathlib.Path(__file__).parent.glob("*.py"):
    if test_file.name not in file_ignore_list:
        print("Running {}".format(test_file))
        sub_process = subprocess.run(
            [sys.executable if sys.executable else "python", str(test_file)]
        )
        sub_process.check_returncode()
