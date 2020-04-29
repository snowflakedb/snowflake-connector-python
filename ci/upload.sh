#!/bin/bash -e
#
# Upload Snowflake Connector Python
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/upload_init.sh
upload_package connector
