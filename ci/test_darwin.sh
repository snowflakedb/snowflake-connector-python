#!/bin/bash -e
#
# Test Snowflake Connector on a Darwin Jenkins slave
# NOTES:
#   - Versions to be tested should be passed in as the first argument, e.g: "3.5 3.6". If omitted 3.5-3.8 will be assumed.
#   - This script uses .. to download the newest wheel files from S3

PYTHON_VERSIONS="${1:-3.6 3.7 3.8}"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
PARAMETERS_DIR="${CONNECTOR_DIR}/.github/workflows/parameters/public"

export JUNIT_REPORT_DIR=${SF_REGRESS_LOGS:-$CONNECTOR_DIR}
export COV_REPORT_DIR=${CONNECTOR_DIR}

# Decrypt parameters file
PARAMS_FILE="${PARAMETERS_DIR}/parameters_aws.py.gpg"
[ ${cloud_provider} == azure ] && PARAMS_FILE="${PARAMETERS_DIR}/parameters_azure.py.gpg"
[ ${cloud_provider} == gcp ] && PARAMS_FILE="${PARAMETERS_DIR}/parameters_gcp.py.gpg"
gpg --quiet --batch --yes --decrypt --passphrase="${PARAMETERS_SECRET}" ${PARAMS_FILE} > test/parameters.py

# Run tests
cd $CONNECTOR_DIR
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    echo "[Info] Testing with ${PYTHON_VERSION}"
    SHORT_VERSION=$(python3 -c "print('${PYTHON_VERSION}'.replace('.', ''))")
    CONNECTOR_WHL=$(ls ${CONNECTOR_DIR}/dist/snowflake_connector_python*cp${SHORT_VERSION}*.whl)
    TEST_ENVLIST=py${SHORT_VERSION}-{extras,unit,integ,pandas,sso}-ci
    echo "[Info] Running tox for ${TEST_ENVLIST}"

    # https://github.com/tox-dev/tox/issues/1485
    # tox seems to not work inside virtualenv, so manually installed tox and trigger system default tox
    /Library/Frameworks/Python.framework/Versions/3.5/bin/tox -e ${TEST_ENVLIST} --external_wheels ${CONNECTOR_WHL}
done
