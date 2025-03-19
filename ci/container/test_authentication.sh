#!/bin/bash -e

set -o pipefail


export WORKSPACE=${WORKSPACE:-/mnt/workspace}
export SOURCE_ROOT=${SOURCE_ROOT:-/mnt/host}
MVNW_EXE=$SOURCE_ROOT/mvnw

AUTH_PARAMETER_FILE=./.github/workflows/parameters/private/parameters_aws_auth_tests.json
eval $(jq -r '.authtestparams | to_entries | map("export \(.key)=\(.value|tostring)")|.[]' $AUTH_PARAMETER_FILE)

export SF_OCSP_TEST_MODE=true
export SF_ENABLE_EXPERIMENTAL_AUTHENTICATION=true
export PYTHONPATH=$SOURCE_ROOT

python3 -m pip install --break-system-packages -e .

python3 -m pytest test/auth/test_oauth.py
python3 -m pytest -s test/auth/test_external_browser.py
python3 -m pytest test/auth/test_okta.py