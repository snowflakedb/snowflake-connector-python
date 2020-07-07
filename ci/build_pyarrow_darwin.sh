#!/bin/bash -e
#
# Build Snowflake Connector for Python with extension on mac
#
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
source $THIS_DIR/build_init.sh

function build_connector_with_python() {
    PYTHON=$1
    VIRTUALENV=$WORKSPACE/venv-build-${PYTHON}
    virtualenv -p ${PYTHON} ${VIRTUALENV}
    source $VIRTUALENV/bin/activate
    log INFO "Creating a wheel: snowflake_connector using $PYTHON"
    cd $CONNECTOR_DIR
    rm -rf build/
    export ENABLE_EXT_MODULES=true
    if [[ -n "$RELEASE_PACKAGE" ]]; then
        rm -f generated_version.py || true
    fi
    # This needs to be kept in sync with setup.py
    pip install -U pyarrow==0.17.0 Cython flake8
    flake8
    MACOSX_DEPLOYMENT_TARGET=10.12 python setup.py bdist_wheel -d $CONNECTOR_DIR/dist/
    unset ENABLE_EXT_MODULES
    deactivate
}

PYTHON_VERSIONS="${1:-3.5 3.6 3.7 3.8}"

for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    PYTHON="python${PYTHON_VERSION}"
    build_connector_with_python $PYTHON_VERSION
    log INFO "Creating a wheel: snowflake_connector using $PYTHON"
    cd $CONNECTOR_DIR
done

# build source distribution as well
source $WORKSPACE/venv-build-python3.7/bin/activate
cd $CONNECTOR_DIR
rm -rf dist/
python setup.py sdist
deactivate
