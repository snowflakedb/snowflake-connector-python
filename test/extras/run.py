#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

# This script run every Python file in this directory other than this one in a subprocess
# and checks their exit codes

import pathlib
import subprocess
import sys

for test_file in pathlib.Path(__file__).parent.glob('*.py'):
    if test_file.name != 'run.py':
        print("Running {}".format(test_file))
        sub_process = subprocess.run([sys.executable, str(test_file)])
        sub_process.check_returncode()
