#!/bin/bash -e
#
# Build Snowflake SQLAlchemy for Python
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SQLALCHEMY_DIR="$( dirname "${THIS_DIR}")"
source $THIS_DIR/build_init.sh

cleanup_workspace
is_up_to_date "$SQLALCHEMY_DIR/dist/snowflake_sqlalchemy*$python_svn_revision*.whl" "SQLALCHEMY_DIR" && exit 0
generate_version_file $RELEASE_PACKAGE
create_wheel
if [[ -n "$RELEASE_PACKAGE" ]]; then
    create_sdist
fi
