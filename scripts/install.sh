#!/bin/bash -e
#
# Install Snowflake Python Connector
#
set -o pipefail
sudo apt-get update
openssl aes-256-cbc -k "$super_secret_password" -in parameters.py.enc -out test/parameters.py -d
curl -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py
pip --version
pip install -U virtualenv
python -m virtualenv venv
source ./venv/bin/activate
pip install numpy
pip install pytest pytest-cov pytest-rerunfailures
if [[ "$TRAVIS_PYTHON_VERSION" == "2.7" ]]; then
    pip install mock
fi
pip install .
pip list --format=columns
