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
echo "[diag] PATH=${PATH}"
echo "[diag] SHELL=${SHELL} BASH_VERSION=${BASH_VERSION}"
echo "[diag] stdin is a TTY: $([ -t 0 ] && echo yes || echo no)"

if command -v pyenv &>/dev/null; then
    echo "[diag] pyenv version: $(pyenv --version 2>&1)"
    echo "[diag] pyenv root: $(pyenv root 2>/dev/null || echo 'N/A')"
    echo "[diag] pyenv versions installed:"
    pyenv versions 2>&1 | sed 's/^/[diag]   /'
    echo "[diag] PYENV_VERSION=${PYENV_VERSION:-<unset>}"
    echo "[diag] PYENV_ROOT=${PYENV_ROOT:-<unset>}"
    echo "[diag] .python-version file: $(cat .python-version 2>/dev/null || echo '<none>')"
else
    echo "[diag] pyenv: NOT FOUND"
fi

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

    # Select the pyenv version so the shim resolves to the real binary;
    # without this the shim hangs in non-interactive (Jenkins) environments.
    if command -v pyenv &>/dev/null; then
        # Find the latest installed patch for this minor version
        _pyenv_match=$(pyenv versions --bare 2>/dev/null | grep "^${PYTHON_VERSION}" | tail -1)
        if [ -z "${_pyenv_match}" ]; then
            echo "[ERROR] pyenv has no installed version matching ${PYTHON_VERSION}.*, skipping"
            pyenv versions --bare 2>&1 | sed 's/^/[diag]   available: /'
            continue
        fi
        export PYENV_VERSION="${_pyenv_match}"
        echo "[diag] set PYENV_VERSION=${PYENV_VERSION} (matched from ${PYTHON_VERSION})"
        echo "[diag] pyenv which ${PYTHON} => $(pyenv which ${PYTHON} 2>&1 || echo 'FAILED')"
    fi

    echo "[diag] about to run: ${PYTHON} --version (+$(_elapsed)s)"
    ${PYTHON} --version 2>&1 || { echo "[ERROR] ${PYTHON} not found, skipping"; continue; }
    echo "[diag] ${PYTHON} --version succeeded (+$(_elapsed)s)"

    # Need to create a venv to update build dependencies
    echo "[diag] Creating venv at ${VENV_DIR} ... (+$(_elapsed)s)"
    ${PYTHON} -m venv ${VENV_DIR}
    echo "[diag] venv created (+$(_elapsed)s)"
    source ${VENV_DIR}/bin/activate
    echo "[diag] venv activated — python: $(python --version 2>&1) at $(which python)"
    echo "[diag] venv pip: $(python -m pip --version 2>&1)"

    # Build
    echo "[Info] Creating a wheel: snowflake_connector using $PYTHON"
    rm -rf build generated_version.py

    echo "[diag] pip install -U pip setuptools wheel build ... (+$(_elapsed)s)"
    python -m pip install -U pip setuptools wheel build 2>&1 | tail -5
    echo "[diag] pip install finished (+$(_elapsed)s)"

    echo "[diag] disk free before wheel build:"
    df -h "${CONNECTOR_DIR}" 2>/dev/null || true
    echo "[diag] python -m build --wheel starting ... (+$(_elapsed)s)"
    python -m build --wheel . 2>&1 || {
        echo "[ERROR] wheel build failed for ${PYTHON_VERSION} (+$(_elapsed)s)"
        deactivate; unset PYENV_VERSION; rm -rf ${VENV_DIR}
        continue
    }
    echo "[diag] python -m build --wheel finished (+$(_elapsed)s)"

    echo "[diag] wheels so far in dist/:"
    ls -lh "${DIST_DIR}"/*.whl 2>/dev/null || echo "[diag]   (none)"

    deactivate
    unset PYENV_VERSION
    echo "[diag] Deleting venv at ${VENV_DIR} (+$(_elapsed)s)"
    rm -rf ${VENV_DIR}

    STEP_ELAPSED=$(( $(date +%s) - STEP_START ))
    echo "[diag] Python ${PYTHON_VERSION} completed in ${STEP_ELAPSED}s (total +$(_elapsed)s)"
done

echo ""
echo "[diag] build_darwin.sh finished at $(date -u '+%Y-%m-%dT%H:%M:%SZ') — total $(_elapsed)s"
echo "[diag] wheels built:"
ls -lh "${DIST_DIR}"/*.whl 2>/dev/null || echo "[diag] (no wheels found in ${DIST_DIR})"
