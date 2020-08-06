#!/bin/bash -e
# Start Snowflake Python Connector tests
# NOTES:
#   - This script is used by Jenkins to start various tests
#   - Assumes that py_test_mode And python_env (not required for FIPS tests as of now) were previously set
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
PARAMETERS_DIR="${CONNECTOR_DIR}/.github/workflows/parameters/private"

cd "${CONNECTOR_DIR}"

# Check Requirements
if [ -z "${PARAMETERS_SECRET}" ]; then
    echo "Missing PARAMETERS_SECRET, failing..."
    exit 1
fi

# Decrypt parameters file
PARAMS_FILE="${PARAMETERS_DIR}/parameters_aws.py.gpg"
[ ${cloud_provider} == azure ] && PARAMS_FILE="${PARAMETERS_DIR}/parameters_azure.py.gpg"
[ ${cloud_provider} == gcp ] && PARAMS_FILE="${PARAMETERS_DIR}/parameters_gcp.py.gpg"
gpg --quiet --batch --yes --decrypt --passphrase="${PARAMETERS_SECRET}" ${PARAMS_FILE} > test/parameters.py


# Download artifacts made by build
aws s3 cp --recursive --only-show-errors s3://sfc-jenkins/repository/python_connector/linux/${client_git_branch}/${client_git_commit}/ dist

# Run one of the tests
if [ "${py_test}" = "fips" ]; then
    echo "[Info] Going to run FIPS tests"
    ${THIS_DIR}/test_fips_docker.sh
else
    echo "[Info] Going to run regular tests for Python ${python_env}"
    ${THIS_DIR}/test_docker.sh ${python_env}
fi
