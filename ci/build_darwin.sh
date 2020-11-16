#!/bin/bash -e
#
# Build Snowflake Python Connector on Mac
# NOTES:
#   - To compile only a specific version(s) pass in versions like: `./build_darwin.sh "3.5 3.6"`
PYTHON_VERSIONS="${1:-3.6 3.7 3.8}"
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
DIST_DIR="$CONNECTOR_DIR/dist"

cd $CONNECTOR_DIR
# Clean up previously built DIST_DIR
if [ -d "${DIST_DIR}" ]; then
    echo "[WARN] ${DIST_DIR} already existing, deleting it..."
    rm -rf "${DIST_DIR}"
fi
mkdir -p ${DIST_DIR}

# Make sure we build for our lowest target
# Should be kept in sync with .github/worklfows/build_test.yml
export MACOSX_DEPLOYMENT_TARGET="10.13"
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    # Constants and setup
    PYTHON="python${PYTHON_VERSION}"
    VENV_DIR="${CONNECTOR_DIR}/venv-${PYTHON_VERSION}"

    # Need to create a venv to update build dependencies
    ${PYTHON} -m venv ${VENV_DIR}
    source ${VENV_DIR}/bin/activate
    echo "[Info] Created and activated new venv at ${VENV_DIR}"

    # Build
    echo "[Info] Creating a wheel: snowflake_connector using $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py
    # Update PEP-517 dependencies
    python -m pip install -U pip setuptools
    # Use new PEP-517 build
    python -m pip wheel -w ${DIST_DIR} --no-deps .
    deactivate
    echo "[Info] Deleting venv at ${VENV_DIR}"
    rm -rf ${VENV_DIR}
done
