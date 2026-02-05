#!/bin/bash
#
# Test certificate revocation validation using the revocation-validation framework.
# Uses --python-wheel to install from pre-built wheel instead of building from source.
#

set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
WORKSPACE=${WORKSPACE:-${CONNECTOR_DIR}}

echo "[Info] Starting revocation validation tests"
echo "[Info] WORKSPACE: $WORKSPACE"

# ======= FIND PYTHON 3.9+ & SELECT MATCHING WHEEL =======
echo "[Info] ======= PYTHON & WHEEL SELECTION ======="

# Default python3 might be too old (e.g., 3.6), find a supported version (3.9+)
echo "[Info] Default python3: $(which python3) -> $(python3 --version 2>&1)"

# Try to find Python 3.9+ in common locations (newest first)
PYTHON_BIN=""
for v in 3.13 3.12 3.11 3.10 3.9; do
    for p in "/opt/python/${v}/bin/python3" "/usr/bin/python${v}" "/usr/local/bin/python${v}" "python${v}"; do
        if command -v "$p" &>/dev/null; then
            PYTHON_BIN="$p"
            echo "[Info] Found Python ${v}: ${PYTHON_BIN}"
            break 2
        fi
    done
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[Error] No Python 3.9+ found! Wheels require Python 3.9, 3.10, 3.11, 3.12, or 3.13"
    exit 1
fi

# Add found Python to PATH so Go tool uses it
PYTHON_DIR=$(dirname "$PYTHON_BIN")
export PATH="${PYTHON_DIR}:${PATH}"
echo "[Info] Added to PATH: ${PYTHON_DIR}"
echo "[Info] python3 now: $(which python3) -> $(python3 --version 2>&1)"

# Detect Python version and convert to wheel tag
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
TARGET_PYTHON="cp${PYTHON_VERSION//./}"
echo "[Info] Looking for wheel: ${TARGET_PYTHON}"

# Find wheel matching the system Python version
if [[ "$(uname)" == "Darwin" ]]; then
    WHEEL_FILE=$(find "${WORKSPACE}/dist" "${WORKSPACE}/dist/repaired_wheels" -maxdepth 1 -name "*${TARGET_PYTHON}*macosx*.whl" 2>/dev/null | head -1)
else
    WHEEL_FILE=$(find "${WORKSPACE}/dist/repaired_wheels" "${WORKSPACE}/dist" -maxdepth 1 -name "*${TARGET_PYTHON}*.whl" 2>/dev/null | grep -v macosx | head -1)
fi

if [ -n "$WHEEL_FILE" ]; then
    echo "[Info] Found matching wheel: $(basename "$WHEEL_FILE")"
else
    echo "[Warn] No wheel found for ${TARGET_PYTHON}, listing available wheels..."
fi
echo "[Info] ============================================"

if [ -z "$WHEEL_FILE" ]; then
    echo "[Error] ======= NO MATCHING WHEEL FOUND ======="
    echo "[Error] Looking for ${TARGET_PYTHON} wheel"
    echo "[Info] Make sure to run the build stage first"
    echo "[Debug] Available wheels in dist/:"
    find "${WORKSPACE}/dist" -maxdepth 1 -name "*.whl" 2>/dev/null || echo "  No wheels in dist/"
    echo "[Debug] Available wheels in dist/repaired_wheels/:"
    find "${WORKSPACE}/dist/repaired_wheels" -maxdepth 1 -name "*.whl" 2>/dev/null || echo "  No wheels in dist/repaired_wheels/"
    echo "[Error] ========================================="
    exit 1
fi

echo "[Info] Using wheel: $WHEEL_FILE"

# Enable strict mode now that wheel discovery is done
set -e

# Clone revocation-validation framework
REVOCATION_DIR="/tmp/revocation-validation"
rm -rf "$REVOCATION_DIR"
echo "[Info] Cloning revocation-validation framework..."

# Branch to use (can be overridden via environment variable)
REVOCATION_BRANCH="${REVOCATION_BRANCH:-pcyrek-python-integration}"

# Use authenticated clone if credentials available, otherwise public
if [ -n "$GITHUB_USER" ] && [ -n "$GITHUB_TOKEN" ]; then
    git clone --depth 1 --branch "$REVOCATION_BRANCH" "https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/snowflakedb/revocation-validation.git" "$REVOCATION_DIR"
else
    git clone --depth 1 --branch "$REVOCATION_BRANCH" "https://github.com/snowflakedb/revocation-validation.git" "$REVOCATION_DIR"
fi

echo "[Info] Using revocation-validation branch: $REVOCATION_BRANCH"

cd "$REVOCATION_DIR"

echo "[Info] Current directory: $(pwd)"
echo "[Info] WORKSPACE: ${WORKSPACE}"
echo "[Info] Go version: $(go version)"

# Confirm Python/wheel match
echo "[Info] ======= VERIFICATION ======="
echo "[Info] Python: $(python3 --version 2>&1)"
echo "[Info] Wheel: $(basename "${WHEEL_FILE}")"
echo "[Info] =============================="

# Verify the wheel file exists
echo "[Debug] Checking wheel file exists: ${WHEEL_FILE}"
ls -la "${WHEEL_FILE}" || { echo "[Error] Wheel file not found!"; exit 1; }

# Run revocation validation tests with pre-built wheel
echo "[Info] Running revocation validation tests..."
echo "[Debug] go run args: --client snowflake-python --python-wheel ${WHEEL_FILE} --output ${WORKSPACE}/revocation-results.json --output-html ${WORKSPACE}/revocation-report.html --log-level debug"
go run . --client snowflake-python --python-wheel "${WHEEL_FILE}" --output "${WORKSPACE}/revocation-results.json" --output-html "${WORKSPACE}/revocation-report.html" --log-level debug

EXIT_CODE=$?

echo "[Info] Test exit code: $EXIT_CODE"

# Check if output files were created
if [ -f "${WORKSPACE}/revocation-results.json" ]; then
    echo "[Info] Results JSON created: ${WORKSPACE}/revocation-results.json"
    ls -la "${WORKSPACE}/revocation-results.json"
else
    echo "[Warning] Results JSON NOT found at: ${WORKSPACE}/revocation-results.json"
    echo "[Debug] Checking for files in WORKSPACE:"
    ls -la "${WORKSPACE}/"*.json 2>/dev/null || echo "  No .json files found"
    echo "[Debug] Checking for files in current directory:"
    ls -la *.json 2>/dev/null || echo "  No .json files found"
fi

if [ -f "${WORKSPACE}/revocation-report.html" ]; then
    echo "[Info] HTML report created: ${WORKSPACE}/revocation-report.html"
    ls -la "${WORKSPACE}/revocation-report.html"
else
    echo "[Warning] HTML report NOT found at: ${WORKSPACE}/revocation-report.html"
fi

exit $EXIT_CODE
