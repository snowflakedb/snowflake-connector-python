#!/bin/bash -e
#
# Conda package init
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/build_init.sh
export CONDA_WORKSPACE=/tmp/anaconda_workspace

function init_miniconda() {
    if [[ "$PLATFORM" == "linux" ]]; then
        MINICONDA_INSTALLER=Miniconda3-4.0.5-Linux-x86_64.sh
    elif [[ "$PLATFORM" == "darwin" ]]; then
        MINICONDA_INSTALLER=Miniconda3-4.0.5-MacOSX-x86_64.sh
    else
        log ERROR "No Miniconda is available for this platform: $PLATFORM"
        exit 1
    fi
    rm -rf $CONDA_WORKSPACE || true
    mkdir -p $CONDA_WORKSPACE

    log INFO "Downloading and Installing Miniconda"
    aws s3 cp s3://sfc-dev1-data/dependency/$MINICONDA_INSTALLER $CONDA_WORKSPACE
    cd $CONDA_WORKSPACE
    bash $MINICONDA_INSTALLER -b -p $CONDA_WORKSPACE/miniconda3
    export PATH=$CONDA_WORKSPACE/miniconda3/bin:$PATH
    conda install -y conda-build
}

function build_conda_package() {
    local target=$1
    local package_name=$2

    log INFO "Copying $target to $CONDA_WORKSPACE/src..."
    cp -rp $CONNECTOR_DIR $CONDA_WORKSPACE/src
    rm -f $CONDA_WORKSPACE/src/generated_version.py

    cp -rp $THIS_DIR/anaconda/ $CONDA_WORKSPACE/${package_name}

    log INFO "Building $package_name for Conda"
    cd $CONDA_WORKSPACE
    conda build "$package_name"

    log INFO "Running Install Test: $package_name"
    conda install -y --use-local "$package_name"
    log INFO "Done: Installation Test: $package_name"
}

function upload_conda_package() {
    local target=$1
    local package_name=$2

    read -n1 -p "Are you sure to upload $package_name (y/N)? "
    echo
    if [[ $REPLY != [yY] ]]; then
        log INFO "Good bye!"
        exit 0
    fi

    log INFO "Generate packages for All platforms"
    conda install -y anaconda-client
    ALL_PACKAGE_DIR=$CONDA_WORKSPACE/all_packages
    SOURCE_PACKAGE_FILE=$(ls $CONDA_WORKSPACE/miniconda3/conda-bld/linux-64/${package_name}*)
    conda convert $SOURCE_PACKAGE_FILE -p all -o $ALL_PACKAGE_DIR

    log INFO "Uploading all packages to snowflakedb channel"
    anaconda upload --force --user snowflakedb $ALL_PACKAGE_DIR/*/${package_name}*
}
