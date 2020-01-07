Building and Testing Snowflake Connector for Python
********************************************************************************

Building
================================================================================

Install Python 3.5.0 or higher. Clone the Snowflake Connector for Python repository, then run the following command to create a wheel package:

    .. code-block:: bash

        git clone git@github.com:snowflakedb/snowflake-connector-python.git
        cd snowflake-connector-python
        pyvenv /tmp/test_snowflake_connector_python
        source /tmp/test_snowflake_connector_python/bin/activate
        pip install -U pip setuptools wheel
        python setup.py bdist_wheel

Find the ``snowflake_connector_python*.whl`` package in the ``./dist`` directory.


Testing
================================================================================

Create a virtualenv, with ``parameters.py`` in a test directory. 

    .. code-block:: bash

        pyvenv /tmp/test_snowflake_connector_python
        source /tmp/test_snowflake_connector_python/bin/activate
        pip install Cython pytest numpy pandas mock
        pip install dist/snowflake_connector_python*.whl
        vim test/parameters.py

In the ``parameters.py`` file, include the connection information in a Python dictionary.

    .. code-block:: python

        CONNECTION_PARAMETERS = {
            'account':  'testaccount',
            'user':     'user1',
            'password': 'testpasswd',
            'schema':   'testschema',
            'database': 'testdb',
        }

Run the test:

    .. code-block:: bash

        py.test test
