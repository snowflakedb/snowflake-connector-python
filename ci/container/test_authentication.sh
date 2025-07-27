#!/bin/bash -e

set -o pipefail


export WORKSPACE=${WORKSPACE:-/mnt/workspace}
export SOURCE_ROOT=${SOURCE_ROOT:-/mnt/host}

AUTH_PARAMETER_FILE=./.github/workflows/parameters/private/parameters_aws_auth_tests.json
eval $(jq -r '.authtestparams | to_entries | map("export \(.key)=\(.value|tostring)")|.[]' $AUTH_PARAMETER_FILE)

export SNOWFLAKE_AUTH_TEST_PRIVATE_KEY_PATH=./.github/workflows/parameters/private/rsa_keys/rsa_key.p8
export SNOWFLAKE_AUTH_TEST_INVALID_PRIVATE_KEY_PATH=./.github/workflows/parameters/private/rsa_keys/rsa_key_invalid.p8

export SF_OCSP_TEST_MODE=true
export SF_ENABLE_EXPERIMENTAL_AUTHENTICATION=true
export RUN_AUTH_TESTS=true
export AUTHENTICATION_TESTS_ENV="docker"
export PYTHONPATH=$SOURCE_ROOT

python3 -m pip install --break-system-packages -e .

python3 -m pytest test/auth/*
