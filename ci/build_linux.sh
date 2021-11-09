#!/bin/bash -e
#
# Build Snowflake Python Connector on Linux
# NOTES:
#   - This is designed to ONLY be called in our build docker image
#   - To compile only a specific version(s) pass in versions like: `./build_linux.sh "3.5 3.6"`
set -o pipefail

U_WIDTH=16
PYTHON_VERSIONS="${1:-3.6 3.7 3.8 3.9 3.10}"
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
DIST_DIR="${CONNECTOR_DIR}/dist"
REPAIRED_DIR=${DIST_DIR}/repaired_wheels

cd "$CONNECTOR_DIR"
# Clean up previously built DIST_DIR
if [ -d "${DIST_DIR}" ]; then
    echo "[WARN] ${DIST_DIR} already existing, deleting it..."
    rm -rf "${DIST_DIR}"
fi
mkdir -p ${REPAIRED_DIR}

# Necessary for cpython_path
source /home/user/multibuild/manylinux_utils.sh

for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    # Constants and setup
    PYTHON="$(cpython_path ${PYTHON_VERSION} ${U_WIDTH})/bin/python"
    BUILD_DIR="${DIST_DIR}/$PYTHON_VERSION"

    # Build
    echo "[Info] Building for ${PYTHON_VERSION} with $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py
    # Update PEP-517 dependencies
    ${PYTHON} -m pip install --upgrade pip setuptools wheel build
    # Use new PEP-517 build
    ${PYTHON} -m build --outdir ${BUILD_DIR} .
    # On Linux we should repair wheel(s) generated
arch=$(uname -p)
if [[ $arch == x86_64 ]]; then
  auditwheel repair --plat manylinux2014_x86_64 ${BUILD_DIR}/*.whl -w ${REPAIRED_DIR}
else
  auditwheel repair --plat manylinux2014_aarch64 ${BUILD_DIR}/*.whl -w ${REPAIRED_DIR}
fi

    # Generate reqs files
    FULL_PYTHON_VERSION="$(${PYTHON} --version | cut -d' ' -f2-)"
    REQS_FILE="${BUILD_DIR}/requirements_$(${PYTHON} -c 'from sys import version_info;print(str(version_info.major)+str(version_info.minor))').txt"
    ${PYTHON} -m pip install ${BUILD_DIR}/*.whl
    echo "# Generated on: $(${PYTHON} --version)" >${REQS_FILE}
    echo "# With snowflake-connector-python version: $(${PYTHON} -m pip show snowflake-connector-python | grep ^Version | cut -d' ' -f2-)" >>${REQS_FILE}
    ${PYTHON} -m pip freeze | grep -v snowflake-connector-python 1>>${REQS_FILE} 2>/dev/null
done

# Move lowest Python version generated sdist to right location
mv "${DIST_DIR}"/3.6/*.tar.gz dist
