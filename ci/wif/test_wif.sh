#!/bin/bash -e

set -o pipefail

export SF_OCSP_TEST_MODE=true
export RUN_WIF_TESTS=true

# setup pytest
/opt/python/cp312-cp312/bin/python -m pip install --break-system-packages pytest pytest-asyncio

# test WIF without asyncio installed
/opt/python/cp312-cp312/bin/python -m pip install --break-system-packages -e .
/opt/python/cp312-cp312/bin/python -m pytest test/wif/* --ignore test/wif/test_wif_async.py

# test WIF with asyncio installed
/opt/python/cp312-cp312/bin/python -m pip install --break-system-packages -e '.[aio]'
# run all tests to see whether installation does not break anything
/opt/python/cp312-cp312/bin/python -m pytest test/wif/*
