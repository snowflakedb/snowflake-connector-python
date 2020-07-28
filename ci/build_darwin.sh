#!/bin/bash -e
#
# Build Snowflake Python Connector on Mac
# NOTES:
#   - To compile only a specific version(s) pass in versions like: `./build_darwin.sh "3.5 3.6"`
PYTHON_VERSIONS="${1:-3.5 3.6 3.7 3.8}"
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
export MACOSX_DEPLOYMENT_TARGET="10.12"
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    # Constants and setup
    PYTHON="python${PYTHON_VERSION}"
    BUILD_DIR="${DIST_DIR}/$PYTHON_VERSION/"

    # Build
    log INFO "Creating a wheel: snowflake_connector using $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py
    # Update PEP-517 dependencies
    ${PYTHON} -m pip install -U pip setuptools
    # Use new PEP-517 build
    ${PYTHON} -m pip wheel -w ${BUILD_DIR} --no-deps .
done
