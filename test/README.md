# Building and Testing Snowflake Connector for Python

## Running tests

Place the `parameters.py` file in the `test` directory, with the connection information in a Python dictionary:

```python
CONNECTION_PARAMETERS = {
    'account':  'testaccount',
    'user':     'user',
    'password': 'testpasswd',
    'schema':   'testschema',
    'database': 'testdb',
}
```

### Running a suite of tests

We use `tox` version 4 to run test suites and other utilities.

To run the most important tests, execute:

```shell
tox -e "fix_lint,py39{,-pandas,-sso}"
```

**NOTE** Some integration tests may be sensitive to the cloud provider of the
account that the test suite connects to.  The default `dev` provider acts like
all cloud providers, but you may see some test failures during integration
tests, depending on the actual cloud of the account you are connecting to.  To
eliminate any such false failure, set the environment variable
`cloud_provider` to one of `aws`, `gcp`, or `azure` as appropriate for the
account you're running the integration tests against.  This is handled
correctly in CI so should only affect your local testing.  In the future,
we'll try to make this automatic by querying the account after the connection
is made.

### Running a single test

Enter the tox environment you want (e.g. `py39`) and run `pytest` from there:

```shell
. .tox/py39/bin/activate
pytest -v test/integ/test_connection.py::test_basic
```

## Test types
These test types can be mixed with test categories, or with each other.
Note: providing both to tox runs both integration and unit tests of the current category and not providing
either does the same as providing both of them.

* **integ**: Integration tests that need to connect to a Snowflake environment.
* **unit**: Unit tests that can run locally, but they might still require internet connection.

## Test categories
Chaining these categories is possible, but isn't encouraged.
Note: running multiple categories in one `tox` run should be done like:
`tox -e "fix_lint,py39-{,-sso},coverage"`

* **pandas**: Tests specifically testing our optional dependency group "pandas".
* **sso**: Tests specifically testing our optional dependency group "sso".
* **extras**: Tests special cases under separate processes.

Special categories:
* **skipolddriver**: We run the newest tests on the oldest still supported Python connector to verify that they
still work. However; some behaviors change over time and new features get added. For this reason tests tagged with
this marker will not run with old driver version. Any tests that verify new behavior, or old tests that are changed
to use new features should have this marker on them.

## Other test tags
* **internal**: Tests that should only be run on our internal CI.
* **external**: Tests that should only be run on our external CI.
