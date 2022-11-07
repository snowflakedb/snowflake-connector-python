#!/bin/bash -e
#
# Test Snowflake Connector
# Note this is the script that test_docker.sh runs inside of the docker container
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# shellcheck disable=SC1090
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
CONNECTOR_WHL="$(ls $CONNECTOR_DIR/dist/*cp38*manylinux2014*.whl | sort -r | head -n 1)"

python3.8 -m venv fips_env
source fips_env/bin/activate
pip install -U setuptools pip
pip install "snowflake-connector-python[pandas,secure-local-storage,development]==2.7.9" "cryptography<3.3.0" --force-reinstall --no-binary cryptography

echo "!!! Environment description !!!"
echo "Default installed OpenSSL version"
openssl version
python -c "import ssl; print('Python openssl library: ' + ssl.OPENSSL_VERSION)"
python -c  "from cryptography.hazmat.backends.openssl import backend;print('Cryptography openssl library: ' + backend.openssl_version_text())"
python -c  "from cryptography.hazmat.backends import default_backend;print(default_backend())"
pip freeze

cd $CONNECTOR_DIR
pytest -vvv --cov=snowflake.connector --cov-report=xml:coverage.xml test

deactivate
