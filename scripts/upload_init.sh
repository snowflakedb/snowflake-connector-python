#!/bin/bash -e
#
# Upload Python Package to PyPI
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
source $THIS_DIR/build_init.sh

UPLOAD_VIRTUALENV=$VIRTUAL_ENV_DIR/upload_connector

function resetup_upload_env() {
  resetup_env "$UPLOAD_VIRTUALENV"
}

function setup_upload_env() {
  setup_env "$UPLOAD_VIRTUALENV"
}

function upload_package() {
    local target_pkg="connector"

    rm -f $CONNECTOR_DIR/dist/snowflake_${target_pkg}*.whl ||  true
    rm -f $CONNECTOR_DIR/snowflake/${target_pkg}/generated_version.py || true
    rm -rf $CONNECTOR_DIR/snowflake/${target_pkg}/build || true
    rm -f $CONNECTOR_DIR/dist/snowflake{_,-}${target_pkg}*.{whl,tar.gz} || true

    RELEASE_PACKAGE=true $THIS_DIR/build_${target_pkg}.sh -c

    WHL=$(ls $THIS_DIR/dist/snowflake_${target_pkg}*.whl)
    TGZ=$(ls $THIS_DIR/dist/snowflake-${target_pkg}*.tar.gz)

    resetup_upload_env
    source $UPLOAD_VIRTUALENV/bin/activate
    pip install -U twine
    echo "****** $WHL ******"
    echo
    unzip -l $WHL
    echo
    echo "****** $TGZ ******"
    echo
    tar tvfz $TGZ
    log WARN "Verify the package contents. DON'T include any test case or data!"
    if [[ -z "$JENKINS_URL" ]]; then
        # not-jenkins job
        read -n1 -p "Are you sure to upload $WHL (y/N)? "
        echo
        if [[ $REPLY != [yY] ]]; then
            log INFO "Good bye!"
            exit 0
        fi
    fi
    TWINE_OPTIONS=()
    if [[ -n "$TWINE_CONFIG_FILE" ]]; then
        TWINE_OPTIONS=("--config-file" "$TWINE_CONFIG_FILE")
    fi
    # twine register -r pypi $WHL # one time
    twine upload ${TWINE_OPTIONS[@]} -r pypi $WHL
    twine upload ${TWINE_OPTIONS[@]} -r pypi $TGZ
}
