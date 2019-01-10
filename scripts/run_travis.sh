#!/bin/bash -e
#
# Run Travis Tests
#
set -o pipefail
if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    TIMEOUT_CMD=("gtimeout" "-s" "SIGUSR1" "3600s")
else
    TIMEOUT_CMD=("timeout" "-s" "SIGUSR1" "3600s")
fi
source ./venv/bin/activate
ret=0
${TIMEOUT_CMD[@]} py.test -vvv --cov=snowflake.connector test || ret=$?

# TIMEOUT or SUCCESS
[ $ret != 124 -a $ret != 0 ] && exit 1 || exit 0
