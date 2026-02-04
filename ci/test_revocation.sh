#!/bin/bash -e
#
# Test certificate revocation validation using the revocation-validation framework.
# Uses --python-wheel to install from pre-built wheel instead of building from source.
#

set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
WORKSPACE=${WORKSPACE:-${CONNECTOR_DIR}}

# Find pre-built wheel
WHEEL_FILE=$(ls ${WORKSPACE}/dist/*.whl 2>/dev/null | head -1)
if [ -z "$WHEEL_FILE" ]; then
    WHEEL_FILE=$(ls ${WORKSPACE}/dist/repaired_wheels/*.whl 2>/dev/null | head -1)
fi

if [ -z "$WHEEL_FILE" ]; then
    echo "[Error] No wheel found in dist/ or dist/repaired_wheels/"
    echo "[Info] Make sure to run the build stage first"
    exit 1
fi

echo "[Info] Using wheel: $WHEEL_FILE"

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

# Run revocation validation tests with pre-built wheel
echo "[Info] Running revocation validation tests..."
go run . \
    --client snowflake-python \
    --python-wheel "${WHEEL_FILE}" \
    --output "${WORKSPACE}/revocation-results.json" \
    --output-html "${WORKSPACE}/revocation-report.html" \
    --log-level info

EXIT_CODE=$?

echo "[Info] Tests completed. Results saved to:"
echo "  - ${WORKSPACE}/revocation-results.json"
echo "  - ${WORKSPACE}/revocation-report.html"

exit $EXIT_CODE
