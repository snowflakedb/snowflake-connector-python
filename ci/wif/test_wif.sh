#!/bin/bash -e

set -o pipefail

export SF_OCSP_TEST_MODE=true
export RUN_WIF_TESTS=true

#setup pytest
/opt/python/cp39-cp39/bin/python -m pip install --break-system-packages pytest pytest-asyncio

# test WIF without asyncio installed
/opt/python/cp39-cp39/bin/python -m pip install --break-system-packages -e .
/opt/python/cp39-cp39/bin/python -m pytest test/wif/* --ignore test/wif/*_async.py

# test WIF with asyncio installed
/opt/python/cp39-cp39/bin/python -m pip install --break-system-packages -e '.[aio]'
/opt/python/cp39-cp39/bin/python -m pytest test/wif/*
