#!/bin/bash -e

set -o pipefail

export SF_OCSP_TEST_MODE=true
export RUN_WIF_TESTS=true

# setup pytest
/opt/python/cp312-cp312/bin/python -m pip install --break-system-packages pytest pytest-asyncio

# test WIF without asyncio installed
/opt/python/cp312-cp312/bin/python -m pip install --break-system-packages -e .
/opt/python/cp312-cp312/bin/python -m pytest test/wif/ --ignore test/wif/test_wif_async.py

# temporarily disable aio
# # test WIF with asyncio installed
# /opt/python/cp312-cp312/bin/python -m pip install --break-system-packages -e '.[aio]'
# /opt/python/cp312-cp312/bin/python -m pytest test/wif/
