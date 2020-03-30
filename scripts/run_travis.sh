#!/bin/bash -e
#
# Run Travis Tests
#

# shellcheck disable=SC2034
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

set -o pipefail
if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    TIMEOUT_CMD=("gtimeout" "-s" "SIGUSR1" "3600s")
else
    TIMEOUT_CMD=("timeout" "-s" "SIGUSR1" "3600s")
fi
source ./venv/bin/activate
ret=0
if [ -n "$SNOWFLAKE_AZURE" ]; then
  echo "Running Azure tests only..."
  # shellcheck disable=SC2068
  ${TIMEOUT_CMD[@]} py.test -vvv --cov=snowflake.connector \
  --cov-report=xml:python_connector_${TRAVIS_PYTHON_VERSION}_coverage.xml \
  -m "putget" test || ret=$?
elif [ -n "$SNOWFLAKE_GCP" ]; then
  echo "Running GCP tests only..."
  # shellcheck disable=SC2068
  ${TIMEOUT_CMD[@]} py.test -vvv --cov=snowflake.connector \
  --cov-report=xml:python_connector_${TRAVIS_PYTHON_VERSION}_coverage.xml \
  -m "putget" test || ret=$?
else
  echo "Running regular tests..."
  # shellcheck disable=SC2068
  ${TIMEOUT_CMD[@]} py.test -vvv --cov=snowflake.connector \
  --cov-report=xml:python_connector_${TRAVIS_PYTHON_VERSION}_coverage.xml \
  --ignore=test/pandas --ignore=test/sso test || ret=$?
fi

# TIMEOUT or SUCCESS
[ $ret != 124 -a $ret != 0 ] && exit 1 || exit 0
