#!/bin/bash -e
#
# Build Snowflake Connector for Python in our manylinux docker image
#

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
source $THIS_DIR/build_init.sh

function build_connector_with_python() {
    PYTHON=$1
    source "/home/user/venv-build-${PYTHON}/bin/activate"
    log INFO "Creating a wheel: snowflake_connector using $PYTHON $U_WIDTH"
    cd $CONNECTOR_DIR
    rm -rf build/
    export ENABLE_EXT_MODULES=true
    rm -f generated_version.py
    flake8
    python setup.py bdist_wheel -d $CONNECTOR_DIR/dist/docker/$PYTHON/
    unset ENABLE_EXT_MODULES

    # audit wheel files
    mkdir -p $CONNECTOR_DIR/dist/docker/repaired_wheels
    auditwheel repair --plat manylinux2010_x86_64 -L connector $CONNECTOR_DIR/dist/docker/$PYTHON/*.whl -w $CONNECTOR_DIR/dist/docker/repaired_wheels
    deactivate
}

if [[ -n "$CLEAN" ]]; then
    log WARN "Deleting artifacts for Python Connector in $CONNECTOR_DIR/build, $CONNECTOR_DIR/dist"
    rm -rf $CONNECTOR_DIR/build || true
    rm -rf $CONNECTOR_DIR/dist/snowflake{_,-}connector* || true
fi
generate_version_file "$RELEASE_PACKAGE"

cd $CONNECTOR_DIR
rm -rf dist/docker/

PYTHON_VERSION=$1

# if no arguments provided to this script, by default we will build using all versions
# of python connector
if [[ -z $PYTHON_VERSION ]] || [[ $PYTHON_VERSION == 'all' ]]; then
    PYTHON_VERSIONS=("3.5" "3.6" "3.7" "3.8")
else
    PYTHON_VERSIONS=($PYTHON_VERSION)
fi

for PYTHON_TUPLE in ${PYTHON_VERSIONS[@]}; do
    build_connector_with_python "$PYTHON_TUPLE"
    source /home/user/multibuild/manylinux_utils.sh
    generate_reqs_file /opt/python/cp35-cp35m/bin/virtualenv "$(cpython_path $PYTHON 16)/bin/python" "$(latest_wheel $CONNECTOR_DIR/dist/docker/$PYTHON/*.whl)" "/home/user/py${PYTHON_TUPLE}_tmp_env"
    # Move .reqs files into new directories as per SNOW-122208
    full_python_version="$($(cpython_path $PYTHON 16)/bin/python --version | cut -d' ' -f2-)"
    mkdir "${CONNECTOR_DIR}/dist/docker/${full_python_version}"
    log INFO "Going to move reqs file to $CONNECTOR_DIR/dist/docker/$full_python_version for full version number"
    mv ${CONNECTOR_DIR}/dist/docker/${PYTHON}/*.reqs "${CONNECTOR_DIR}/dist/docker/${full_python_version}/"
done
