Snowflake Connector for Python
********************************************************************************

.. image:: https://github.com/snowflakedb/snowflake-connector-python/workflows/Build%20and%20Test/badge.svg?branch=master
    :target: https://github.com/snowflakedb/snowflake-connector-python/actions?query=workflow%3A%22Build+and+Test%22+branch%3Amaster

.. image:: https://codecov.io/gh/snowflakedb/snowflake-connector-python/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/snowflakedb/snowflake-connector-python

.. image:: https://img.shields.io/pypi/v/snowflake-connector-python.svg
    :target: https://pypi.python.org/pypi/snowflake-connector-python/

.. image:: http://img.shields.io/:license-Apache%202-brightgreen.svg
    :target: http://www.apache.org/licenses/LICENSE-2.0.txt

This package includes the Snowflake Connector for Python, which conforms to the Python DB API 2.0 specification:
https://www.python.org/dev/peps/pep-0249/

The Snowflake Connector for Python provides an interface for developing Python
applications that can connect to Snowflake and perform all standard operations. It
provides a programming alternative to developing applications in Java or C/C++
using the Snowflake JDBC or ODBC drivers.

The connector is a native, pure Python package that has no dependencies on JDBC or
ODBC. It can be installed using ``pip`` on Linux, Mac OSX, and Windows platforms
where Python 3.6.0 (or higher) is installed.

Snowflake Documentation is available at:
https://docs.snowflake.com/

Feel free to file an issue or submit a PR here for general cases. For official support, contact Snowflake support at:
https://community.snowflake.com/s/article/How-To-Submit-a-Support-Case-in-Snowflake-Lodge
