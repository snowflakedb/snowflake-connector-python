#!/bin/bash -e
#
# Test Snowflake Connector
# Note this is the script that test_docker.sh runs inside of the docker container
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# shellcheck disable=SC1090
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
CONNECTOR_WHL="$(ls $CONNECTOR_DIR/dist/*cp38*manylinux2014*.whl | sort -r | head -n 1)"

python3.8 -m venv lambda_env
source lambda_env/bin/activate
pip install -U setuptools pip tox tox-external_wheels
pip install "${CONNECTOR_WHL}[pandas,secure-local-storage,development]"

echo "!!! Environment description !!!"
echo "Default installed OpenSSL version"
openssl version
python -c "import ssl; print('Python openssl library: ' + ssl.OPENSSL_VERSION)"
python -c  "from cryptography.hazmat.backends.openssl import backend;print('Cryptography openssl library: ' + backend.openssl_version_text())"
pip freeze


# Run tests
cd $CONNECTOR_DIR
python -m tox -e py38{-lambda}-ci -c ${CONNECTOR_DIR}/tox.ini --external_wheels ${CONNECTOR_WHL}

deactivate
