Building and Testing Snowflake Connector for Python
********************************************************************************

Building
================================================================================

Install Python 2.7.9 or higher, or 3.4.3 or higher. Clone the Snowflake Connector for Python repository, then run the following command to create a wheel package:

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

WIP
