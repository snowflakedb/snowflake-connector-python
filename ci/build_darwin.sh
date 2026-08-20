#!/bin/bash -e -l
#
# Build Snowflake Python Connector on Mac
# NOTES:
#   - To compile only a specific version(s) pass in versions like: `./build_darwin.sh "3.10 3.11"`
PYTHON_VERSIONS="${1:-3.10 3.11 3.12 3.13 3.14 3.14t}"

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
DIST_DIR="$CONNECTOR_DIR/dist"

# Print a timestamped info message
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "[Info] Starting build_darwin.sh"
log "[Info] Host: $(uname -a)"
log "[Info] Python versions to build: ${PYTHON_VERSIONS}"

cd $CONNECTOR_DIR
# Clean up previously built DIST_DIR
if [ -d "${DIST_DIR}" ]; then
    log "[WARN] ${DIST_DIR} already existing, deleting it..."
    rm -rf "${DIST_DIR}"
fi
mkdir -p ${DIST_DIR}

# Make sure we build for our lowest target
# Should be kept in sync with .github/worklfows/build_test.yml
export MACOSX_DEPLOYMENT_TARGET="10.14"
for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    # Constants and setup
    PYTHON="python${PYTHON_VERSION}"
    VENV_DIR="${CONNECTOR_DIR}/venv-${PYTHON_VERSION}"

    log "[Info] ===== Starting build for Python ${PYTHON_VERSION} ====="

    unset PYENV_VERSION

    # Select the matching pyenv-installed version (e.g. 3.10 -> 3.10.15).
    # Free-threaded builds may be reported as e.g. "3.14t" or "3.14.0t" depending on the
    # pyenv-build convention, so match either shape for a "*t" version.
    if command -v pyenv &> /dev/null; then
        if [[ "${PYTHON_VERSION}" == *t ]]; then
            PYENV_BASE="${PYTHON_VERSION%t}"
            PYENV_PATTERN="^${PYENV_BASE//./\\.}(\\.[0-9]+)?t\$"
        else
            PYENV_PATTERN="^${PYTHON_VERSION//./\\.}(\\.[0-9]+)?\$"
        fi
        PYENV_MATCH=$(pyenv versions --bare | grep -E "${PYENV_PATTERN}" | tail -1)
        if [ -n "$PYENV_MATCH" ]; then
            pyenv local "$PYENV_MATCH"
            # `pyenv local` alone is not enough: the shim can hang in a non-interactive
            # shell (no TTY) if it has to re-resolve the version on every invocation.
            # Exporting PYENV_VERSION makes the shim resolve it directly. See ed53f0cf
            # ("Fix pyenv shim hang on Jenkins by selecting PYENV_VERSION per iteration").
            export PYENV_VERSION="$PYENV_MATCH"
            log "[Info] pyenv version set to $PYENV_MATCH"
        else
            log "[WARN] no pyenv-installed version matches ${PYTHON_VERSION}, relying on PATH"
        fi
    fi

    log "[Info] Checking if ${PYTHON} is available..."
    which ${PYTHON} || { log "[ERROR] ${PYTHON} not found in PATH, skipping"; continue; }
    ${PYTHON} --version

    # Need to create a venv to update build dependencies
    log "[Info] Creating venv at ${VENV_DIR}..."
    ${PYTHON} -m venv ${VENV_DIR}
    source ${VENV_DIR}/bin/activate
    log "[Info] Created and activated new venv at ${VENV_DIR}"

    # Build
    log "[Info] Creating a wheel: snowflake_connector using $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py
    # Update PEP-517 dependencies
    log "[Info] Upgrading pip, setuptools, wheel, build..."
    python -m pip install -U pip setuptools wheel build
    log "[Info] pip install complete"
    # Use new PEP-517 build
    log "[Info] Running python -m build --wheel ..."
    python -m build --wheel .
    log "[Info] python -m build complete"
    deactivate
    unset PYENV_VERSION
    log "[Info] Deleting venv at ${VENV_DIR}"
    rm -rf ${VENV_DIR}
    log "[Info] ===== Finished build for Python ${PYTHON_VERSION} ====="
done

log "[Info] build_darwin.sh finished successfully"
