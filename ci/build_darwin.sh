#!/bin/bash -e
#
# Build Snowflake Python Connector on Mac
# NOTES:
#   - To compile only a specific version(s) pass in versions like: `./build_darwin.sh "3.9 3.10"`
PYTHON_VERSIONS="${1:-3.9 3.10 3.11 3.12 3.13 3.14}"

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
DIST_DIR="$CONNECTOR_DIR/dist"

BUILD_START=$(date +%s)
_elapsed() { echo $(( $(date +%s) - BUILD_START )); }

echo "[diag] build_darwin.sh started at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "[diag] hostname=$(hostname) user=$(whoami) arch=$(uname -m) os=$(sw_vers -productVersion 2>/dev/null || uname -r)"
echo "[diag] PYTHON_VERSIONS=${PYTHON_VERSIONS}"
echo "[diag] CONNECTOR_DIR=${CONNECTOR_DIR}"
echo "[diag] disk free (CONNECTOR_DIR):"
df -h "${CONNECTOR_DIR}" 2>/dev/null || true

cd $CONNECTOR_DIR
# Clean up previously built DIST_DIR
if [ -d "${DIST_DIR}" ]; then
    echo "[WARN] ${DIST_DIR} already existing, deleting it..."
    rm -rf "${DIST_DIR}"
fi
mkdir -p ${DIST_DIR}

# Make sure we build for our lowest target
# Should be kept in sync with .github/worklfows/build_test.yml
export MACOSX_DEPLOYMENT_TARGET="10.14"
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    STEP_START=$(date +%s)
    # Constants and setup
    PYTHON="python${PYTHON_VERSION}"
    VENV_DIR="${CONNECTOR_DIR}/venv-${PYTHON_VERSION}"

    echo ""
    echo "[diag] ======== Python ${PYTHON_VERSION} ======== (+$(_elapsed)s elapsed)"
    echo "[diag] which ${PYTHON} => $(which ${PYTHON} 2>/dev/null || echo 'NOT FOUND')"
    ${PYTHON} --version 2>&1 || { echo "[ERROR] ${PYTHON} not found, skipping"; continue; }

    # Need to create a venv to update build dependencies
    echo "[diag] Creating venv at ${VENV_DIR} ... (+$(_elapsed)s)"
    ${PYTHON} -m venv ${VENV_DIR}
    source ${VENV_DIR}/bin/activate
    echo "[Info] Created and activated new venv at ${VENV_DIR}"
    echo "[diag] venv python: $(python --version 2>&1) at $(which python)"

    # Build
    echo "[Info] Creating a wheel: snowflake_connector using $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py

    echo "[diag] pip install starting ... (+$(_elapsed)s)"
    # Update PEP-517 dependencies
    python -m pip install -U pip setuptools wheel build
    echo "[diag] pip install finished (+$(_elapsed)s)"

    echo "[diag] python -m build --wheel starting ... (+$(_elapsed)s)"
    # Use new PEP-517 build
    python -m build --wheel .
    echo "[diag] python -m build --wheel finished (+$(_elapsed)s)"

    deactivate
    echo "[Info] Deleting venv at ${VENV_DIR}"
    rm -rf ${VENV_DIR}

    STEP_ELAPSED=$(( $(date +%s) - STEP_START ))
    echo "[diag] Python ${PYTHON_VERSION} completed in ${STEP_ELAPSED}s (total +$(_elapsed)s)"
done

echo ""
echo "[diag] build_darwin.sh finished at $(date -u '+%Y-%m-%dT%H:%M:%SZ') — total $(_elapsed)s"
echo "[diag] wheels built:"
ls -lh "${DIST_DIR}"/*.whl 2>/dev/null || echo "[diag] (no wheels found in ${DIST_DIR})"
