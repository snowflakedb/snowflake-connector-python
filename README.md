# Snowflake Connector for Python

[![Build and Test](https://github.com/snowflakedb/snowflake-connector-python/actions/workflows/build_test.yml/badge.svg)](https://github.com/snowflakedb/snowflake-connector-python/actions/workflows/build_test.yml)
[![codecov](https://codecov.io/gh/snowflakedb/snowflake-connector-python/branch/main/graph/badge.svg?token=MVKSNtnLr0)](https://codecov.io/gh/snowflakedb/snowflake-connector-python)
[![PyPi](https://img.shields.io/pypi/v/snowflake-connector-python.svg)](https://pypi.python.org/pypi/snowflake-connector-python/)
[![License Apache-2.0](https://img.shields.io/:license-Apache%202-brightgreen.svg)](http://www.apache.org/licenses/LICENSE-2.0.txt)
[![Codestyle Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

This package includes the Snowflake Connector for Python, which conforms to the [Python DB API 2.0](https://www.python.org/dev/peps/pep-0249/) specification.

The Snowflake Connector for Python provides an interface for developing Python
applications that can connect to Snowflake and perform all standard operations. It
provides a programming alternative to developing applications in Java or C/C++
using the Snowflake JDBC or ODBC drivers.

The connector has **no** dependencies on JDBC or ODBC.
It can be installed using ``pip`` on Linux, Mac OSX, and Windows platforms
where Python 3.9.0 (or higher) is installed.

Snowflake Documentation is available at:
https://docs.snowflake.com/

Feel free to file an issue or submit a PR here for general cases. For official support, contact Snowflake support at:
https://community.snowflake.com/s/article/How-To-Submit-a-Support-Case-in-Snowflake-Lodge

## How to build

### Locally

Install a supported Python version. Clone the Snowflake Connector for Python repository, then run the following commands
to create a wheel package using PEP-517 build:

```shell
git clone git@github.com:snowflakedb/snowflake-connector-python.git
cd snowflake-connector-python
python -m pip install -U pip setuptools wheel build
python -m build --wheel .
```

Find the `snowflake_connector_python*.whl` package in the `./dist` directory.

### In Docker
Or use our Dockerized build script `ci/build_docker.sh` and find the built wheel files in `dist/repaired_wheels`.

Note: `ci/build_docker.sh` can be used to compile only certain versions, like this: `ci/build_docker.sh "3.9 3.10"`

## Code hygiene and other utilities
These tools are integrated into `tox` to allow us to easily set them up universally on any computer.

* **fix_lint**: Runs `pre-commit` to check for a bunch of lint issues. This can be installed to run upon each
  time a commit is created locally, keep an eye out for the hint that this environment prints upon succeeding.
* **coverage**: Runs `coverage.py` to combine generated coverage data files. Useful when multiple categories were run
  and we would like to have an overall coverage data file created for them.
* **flake8**: (Deprecated) Similar to `fix_lint`, but only runs `flake8` checks.

## Disable telemetry

By default, the Snowflake Connector for Python collects telemetry data to improve the product.
You can disable the telemetry data collection by setting the session parameter `CLIENT_TELEMETRY_ENABLED` to `False`
when connecting to Snowflake:
```python
import snowflake.connector
conn = snowflake.connector.connect(
    user='XXXX',
    password='XXXX',
    account='XXXX',
    session_parameters={
      "CLIENT_TELEMETRY_ENABLED": False,
    }
)
```

Alternatively, you can disable the telemetry data collection
by setting the `telemetry_enabled` property to `False` on the `SnowflakeConnection` object:
```python
import snowflake.connector
conn = snowflake.connector.connect(
    user='XXXX',
    password='XXXX',
    account='XXXX',
)
conn.telemetry_enabled = False
```

## Verifying Package Signatures

To ensure the authenticity and integrity of the Python package, follow the steps below to verify the package signature using `cosign`.

**Steps to verify the signature:**
- Install cosign:
  - This example is using golang installation: [installing-cosign-with-go](https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-install-cosign/#installing-cosign-with-go)
- Download the file from the repository like pypi:
  - https://pypi.org/project/snowflake-connector-python/#files
- Download the signature files from the release tag, replace the version number with the version you are verifying:
  - https://github.com/snowflakedb/snowflake-connector-python/releases/tag/v3.12.2
- Verify signature:
  ````bash
  # replace the version number with the version you are verifying
  ./cosign verify-blob snowflake_connector_python-3.12.2.tar.gz \
  --key snowflake-connector-python-v3.12.2.pub \
  --signature resources.linux.snowflake_connector_python-3.12.2.tar.gz.sig

  Verified OK
  ````

## NOTE

This library currently does not support GCP regional endpoints.  Please ensure that any workloads using through this library do not require support for regional endpoints on GCP.  If you have questions about this, please contact [Snowflake Support](https://community.snowflake.com/s/article/How-To-Submit-a-Support-Case-in-Snowflake-Lodge).
