#!/bin/bash -e
# Start Snowflake Python Connector tests
# NOTES:
#   - This script is used by Jenkins to start various tests
#   - Assumes that py_test_mode And python_env (not required for FIPS tests as of now) were previously set
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARAMETERS_DIR="${THIS_DIR}/.github/workflows/parameters"
PARAM_FILE="${PARAMETERS_DIR}/parameters.py.gpg"

# Check Requirements
if [ -z "${PARAMETERS_SECRET}" ]; then
    echo "Missing PARAMETERS_SECRET, failing..."
    exit 1
fi

# Decrypt parameters file
gpg gpg --quiet --batch --yes --decrypt --passphrase="${PARAMETERS_SECRET}" parameters.py.gpg "${PARAM_FILE}" > test/parameters.py
# Run one of the tests
if [ "${py_test}" = "fips" ]; then
    ${THIS_DIR}/test_fips_docker.sh
else
    ${THIS_DIR}/test_docker.sh ${python_env}
fi


