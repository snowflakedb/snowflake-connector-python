#!/bin/bash -e
#
# Build Snowflake Connector for Anaconda
#

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/conda_init.sh

init_miniconda
build_conda_package connector snowflake_connector_python
upload_conda_package connector snowflake_connector_python
