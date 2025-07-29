#!/bin/bash -e

set -o pipefail

export SF_OCSP_TEST_MODE=true
export SF_ENABLE_EXPERIMENTAL_AUTHENTICATION=true
export RUN_WIF_TESTS=true

/opt/python/cp39-cp39/bin/python -m pip install --break-system-packages -e .
/opt/python/cp39-cp39/bin/python -m pip install --break-system-packages pytest
/opt/python/cp39-cp39/bin/python -m pytest test/wif/*
