Building and Testing Snowflake Connector for Python
********************************************************************************

Testing setup
================================================================================

We use ``tox`` to run tests and other code hygiene related utilities.
Please make sure that you have it installed.

Building
================================================================================

This isn't necessary, as ``tox`` is able to generate source distribution and then install
the library from that.

However, if necessary here we document how to build ``snowflake-connector-python`` locally for the current architecture.
Install Python 3.5.0 or higher. Clone the Snowflake Connector for Python repository, then run the following commands
to create a wheel package using PEP-517 build:

    .. code-block:: bash

        git clone git@github.com:snowflakedb/snowflake-connector-python.git
        cd snowflake-connector-python
        pip install -U pip setuptools wheel
        pip wheel -w dist --no-deps .

Find the ``snowflake_connector_python*.whl`` package in the ``./dist`` directory.

Or use our Dockerized build script ``ci/build_docker.sh`` and find the built wheel files in ``dist/repaired_wheels``.

Note: ``ci/build_docker.sh`` can be used to compile only certain versions, like this: ``ci/build_docker.sh "3.6 3.7"``

Test types
================================================================================
These categories can be mixed with test categories, or with each other.
Note: providing both to tox runs both integration and unit tests of the current category and not providing
either does the same as providing both of them.

* **integ**: Integration tests that need to connect to a Snowflake environment.
* **unit**: Unit tests that can run locally, but they might still require internet connection.

Test categories
================================================================================
Chaining these categories is possible, but isn't encouraged.
Note: running multiple categories in one ``tox`` run should be done like:
``tox -e "fix_lint,py36-{-extras,,-sso},coverage"``

* **pandas**: Tests specifically testing our optional dependency group "pandas".
* **sso**: Tests specifically testing our optional dependency group "sso".
* **extras**: Tests special cases under separate processes.

Code hygiene and other utilities
================================================================================
These tools are integrated into ``tox`` to allow us to easily set them up universally on any computer.

* **fix_lint**: Runs ``precommit-hooks`` to check for a bunch of lint issues. This can be installed to run upon each
  time a commit is created locally, keep an eye out for the hint that this environment prints upon succeeding.
* **coverage**: Runs ``coverage.py`` to combine generated coverage data files. Useful when multiple categories were run
  and we would like to have an overall coverage data file created for them.
* **flake8**: (Deprecated) Similar to fix_lint, but only runs flake8 checks.

Testing
================================================================================

Place the ``parameters.py`` file in the ``test`` directory, with the connection information in a Python dictionary:

    .. code-block:: python

        CONNECTION_PARAMETERS = {
            'account':  'testaccount',
            'user':     'user1',
            'password': 'testpasswd',
            'schema':   'testschema',
            'database': 'testdb',
        }

Run the most important tests:

    .. code-block:: bash

        tox -e "fix_lint,py36{,-pandas,-sso}"
