#!/bin/bash -e -l
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

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] (+$(_elapsed)s) $*"
}

log "[Info] Starting build_darwin.sh"
log "[Info] Host: $(uname -a)"
log "[Info] Python versions to build: ${PYTHON_VERSIONS}"
log "[diag] hostname=$(hostname) user=$(whoami) arch=$(uname -m) os=$(sw_vers -productVersion 2>/dev/null || uname -r)"
log "[diag] PATH=${PATH}"
log "[diag] disk free (CONNECTOR_DIR):"
df -h "${CONNECTOR_DIR}" 2>/dev/null || true

if command -v pyenv &>/dev/null; then
    log "[diag] pyenv version: $(pyenv --version 2>&1)"
    log "[diag] pyenv root: $(pyenv root 2>/dev/null || echo 'N/A')"
    log "[diag] pyenv versions installed:"
    pyenv versions 2>&1 | sed 's/^/  /'
else
    log "[diag] pyenv: NOT FOUND"
fi

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
    STEP_START=$(date +%s)
    # Constants and setup
    PYTHON="python${PYTHON_VERSION}"
    VENV_DIR="${CONNECTOR_DIR}/venv-${PYTHON_VERSION}"

    log "[Info] ===== Starting build for Python ${PYTHON_VERSION} ====="

    # Select the matching pyenv-installed version (e.g. 3.9 -> 3.9.21)
    if command -v pyenv &>/dev/null; then
        PYENV_MATCH=$(pyenv versions --bare 2>/dev/null | grep "^${PYTHON_VERSION//./\\.}" | tail -1)
        if [ -n "$PYENV_MATCH" ]; then
            export PYENV_VERSION="${PYENV_MATCH}"
            log "[Info] set PYENV_VERSION=${PYENV_VERSION}"
        else
            log "[ERROR] pyenv has no installed version matching ${PYTHON_VERSION}.*, skipping"
            pyenv versions --bare 2>&1 | sed 's/^/  available: /'
            continue
        fi
    fi

    log "[Info] Checking if ${PYTHON} is available..."
    which ${PYTHON} || { log "[ERROR] ${PYTHON} not found in PATH, skipping"; unset PYENV_VERSION; continue; }
    ${PYTHON} --version 2>&1

    # Need to create a venv to update build dependencies
    log "[Info] Creating venv at ${VENV_DIR}..."
    ${PYTHON} -m venv ${VENV_DIR}
    source ${VENV_DIR}/bin/activate
    log "[Info] Created and activated new venv at ${VENV_DIR}"
    log "[diag] venv python: $(python --version 2>&1) at $(which python)"

    # Build
    log "[Info] Creating a wheel: snowflake_connector using $PYTHON"
    # Clean up possible build artifacts
    rm -rf build generated_version.py
    # Update PEP-517 dependencies
    log "[Info] Upgrading pip, setuptools, wheel, build..."
    python -m pip install -U pip setuptools wheel build 2>&1 | tail -5
    log "[Info] pip install complete"
    # Use new PEP-517 build
    log "[Info] Running python -m build --wheel ..."
    python -m build --wheel . 2>&1 || {
        log "[ERROR] wheel build failed for ${PYTHON_VERSION}"
        deactivate; unset PYENV_VERSION; rm -rf ${VENV_DIR}
        continue
    }
    log "[Info] python -m build complete"
    deactivate
    unset PYENV_VERSION
    log "[Info] Deleting venv at ${VENV_DIR}"
    rm -rf ${VENV_DIR}

    STEP_ELAPSED=$(( $(date +%s) - STEP_START ))
    log "[Info] ===== Finished build for Python ${PYTHON_VERSION} in ${STEP_ELAPSED}s ====="
done

log "[Info] build_darwin.sh finished successfully — total $(_elapsed)s"
log "[Info] wheels built:"
ls -lh "${DIST_DIR}"/*.whl 2>/dev/null || log "[WARN] no wheels found in ${DIST_DIR}"
