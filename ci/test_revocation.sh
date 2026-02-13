#!/bin/bash
#
# Test certificate revocation validation using the revocation-validation framework.
#

set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
WORKSPACE=${WORKSPACE:-${CONNECTOR_DIR}}

echo "[Info] Starting revocation validation tests"

# Find Python 3.10+ (check /opt/sfc/ first for Snowflake Jenkins nodes)
PYTHON_BIN=""
for v in 3.11 3.10 3.14 3.13 3.12; do
    for p in "/opt/sfc/python${v}/bin/python${v}" "python${v}"; do
        bin=$(command -v "$p" 2>/dev/null || echo "")
        if [ -n "$bin" ] && [ -x "$bin" ]; then
            PYTHON_BIN="$bin"
            break 2
        fi
    done
done

if [ -n "$PYTHON_BIN" ]; then
    TEMP_PYTHON_DIR=$(mktemp -d)
    ln -s "$PYTHON_BIN" "${TEMP_PYTHON_DIR}/python3"
    ln -s "$PYTHON_BIN" "${TEMP_PYTHON_DIR}/python"
    export PATH="${TEMP_PYTHON_DIR}:${PATH}"
fi

echo "[Info] Using Python: $(python3 --version 2>&1)"

# Find matching wheel
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
TARGET_PYTHON="cp${PYTHON_VERSION//./}"

if [[ "$(uname)" == "Darwin" ]]; then
    WHEEL_FILE=$(find "${WORKSPACE}/dist" "${WORKSPACE}/dist/repaired_wheels" -maxdepth 1 -name "*${TARGET_PYTHON}*macosx*.whl" 2>/dev/null | head -1)
else
    WHEEL_FILE=$(find "${WORKSPACE}/dist/repaired_wheels" "${WORKSPACE}/dist" -maxdepth 1 -name "*${TARGET_PYTHON}*.whl" 2>/dev/null | grep -v macosx | head -1)
fi

if [ -z "$WHEEL_FILE" ]; then
    echo "[Error] No wheel found for ${TARGET_PYTHON}"
    echo "[Error] Available wheels:"
    find "${WORKSPACE}/dist" "${WORKSPACE}/dist/repaired_wheels" -maxdepth 1 -name "*.whl" 2>/dev/null || echo "  None"
    exit 1
fi

echo "[Info] Using wheel: $(basename "$WHEEL_FILE")"

set -e

# Clone revocation-validation framework
REVOCATION_DIR="/tmp/revocation-validation"
REVOCATION_BRANCH="${REVOCATION_BRANCH:-main}"

rm -rf "$REVOCATION_DIR"
if [ -n "$GITHUB_USER" ] && [ -n "$GITHUB_TOKEN" ]; then
    git clone --depth 1 --branch "$REVOCATION_BRANCH" "https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/snowflakedb/revocation-validation.git" "$REVOCATION_DIR"
else
    git clone --depth 1 --branch "$REVOCATION_BRANCH" "https://github.com/snowflakedb/revocation-validation.git" "$REVOCATION_DIR"
fi

cd "$REVOCATION_DIR"

echo "[Info] Running tests with Go $(go version | grep -oE 'go[0-9]+\.[0-9]+')..."

go run . \
    --client snowflake-python \
    --python-wheel "${WHEEL_FILE}" \
    --output "${WORKSPACE}/revocation-results.json" \
    --output-html "${WORKSPACE}/revocation-report.html" \
    --log-level debug

EXIT_CODE=$?

if [ -f "${WORKSPACE}/revocation-results.json" ]; then
    echo "[Info] Results: ${WORKSPACE}/revocation-results.json"
fi
if [ -f "${WORKSPACE}/revocation-report.html" ]; then
    echo "[Info] Report: ${WORKSPACE}/revocation-report.html"
fi

exit $EXIT_CODE
