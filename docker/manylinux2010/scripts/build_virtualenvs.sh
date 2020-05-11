#!/bin/bash -e
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Build upon the scripts in https://github.com/matthew-brett/manylinux-builds
# * Copyright (c) 2013-2016, Matt Terry and Matthew Brett (BSD 2-clause)

PYTHON_VERSIONS="${PYTHON_VERSIONS:-3.5 3.6 3.7 3.8}"

source /home/user/multibuild/manylinux_utils.sh

for PYTHON in ${PYTHON_VERSIONS}; do
    U_WIDTH=16
    PYTHON_INTERPRETER="$(cpython_path $PYTHON ${U_WIDTH})/bin/python"
    PIP="$(cpython_path $PYTHON ${U_WIDTH})/bin/pip"
    PATH="$PATH:$(cpython_path $PYTHON ${U_WIDTH})"

    echo "=== Updating pip ==="
    $PIP install -U "pip"

    echo "=== (${PYTHON}, ${U_WIDTH}) Installing build dependencies ==="
    $PIP install "virtualenv"

    echo "=== (${PYTHON}, ${U_WIDTH}) Preparing virtualenv for build ==="
    "$(cpython_path $PYTHON ${U_WIDTH})/bin/virtualenv" -p ${PYTHON_INTERPRETER} --no-download /home/user/venv-build-${PYTHON}
    source /home/user/venv-build-${PYTHON}/bin/activate
    pip install -U pip
    pip install "cython==0.29.15" "setuptools" "flake8" "wheel" "pyarrow==0.17.0"
    deactivate
done

# Remove pip cache again. It's useful during the virtualenv creation but we
# don't want it persisted in the docker layer, ~264MiB
rm -rf /root/.cache
# Remove unused Python versions
rm -rf /opt/_internal/cpython-3.4*
