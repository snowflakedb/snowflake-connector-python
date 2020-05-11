#!/bin/bash -e
#
# Build Snowflake Connector for Python with extension on mac
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
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

PYTHON_VERSION=$1

if [[ -z $PYTHON_VERSION ]]; then
    PYTHON_VERSIONS=("python3.5" "python3.6" "python3.7" "python3.8")
else
    PYTHON_VERSIONS=($PYTHON_VERSION)
fi

for PYTHON_TUPLE in ${PYTHON_VERSIONS[@]}; do
    build_connector_with_python $PYTHON_TUPLE
done

# build source distribution as well
source $WORKSPACE/venv-build-python3.7/bin/activate
cd $CONNECTOR_DIR
rm -rf dist/
python setup.py sdist
deactivate
