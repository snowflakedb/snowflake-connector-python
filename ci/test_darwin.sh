#!/bin/bash -e
#
# Test Snowflake Connector on a Darwin Jenkins slave
# NOTES:
#   - Versions to be tested should be passed in as the first argument, e.g: "3.8 3.9". If omitted 3.8-3.11 will be assumed.
#   - This script uses .. to download the newest wheel files from S3

PYTHON_VERSIONS="${1:-3.8 3.9 3.10 3.11 3.12}"
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

rm -rf venv
python3.12 -m venv venv
. venv/bin/activate
python3.12 -m pip install -U tox>=4

# Run tests
cd $CONNECTOR_DIR
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    echo "[Info] Testing with ${PYTHON_VERSION}"
    SHORT_VERSION=$(python3 -c "print('${PYTHON_VERSION}'.replace('.', ''))")
    CONNECTOR_WHL=$(ls ${CONNECTOR_DIR}/dist/snowflake_connector_python*cp${SHORT_VERSION}*.whl)
    # pandas not tested here because of macos issue: SNOW-1660226
    TEST_ENVLIST=$(python3 -c "print('fix_lint,' + ','.join('py${SHORT_VERSION}-' + e + '-ci' for e in ['unit','integ','sso']) + ',py${SHORT_VERSION}-coverage')")
    echo "[Info] Running tox for ${TEST_ENVLIST}"
    python3.12 -m tox run -e ${TEST_ENVLIST} --installpkg ${CONNECTOR_WHL}
done

deactivate
