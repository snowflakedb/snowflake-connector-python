This package includes the Snowflake Connector for Python, which conforms to the Python DB API 2.0 specification:
https://www.python.org/dev/peps/pep-0249/

Snowflake Documentation is available at:
https://docs.snowflake.net/

Source code is also available at: https://github.com/snowflakedb/snowflake-connector-python

Release Notes
-------------------------------------------------------------------------------

- v1.3.18 (June 15, 2017)

    - Fixed OCSP response cache file not found issue on Windows. Drive letter was taken off
    - Use less restrictive cryptography>=1.7,<1.8
    - Added ORC detection in PUT command

- v1.3.17 (June 1, 2017)

    - Timeout OCSP request in 60 seconds and retry
    - Set autocommit and abort_detached_query session parameters in authentication time if specified
    - Fixed cross region stage issue. Could not get files in us-west-2 region S3 bucket from us-east-1

- v1.3.16 (April 20, 2017)

    - Fixed issue in fetching ``DATE`` causing [Error 22] Invalid argument on Windows
    - Retry on ``RuntimeError`` in requests

- v1.3.15 (March 30, 2017)

    - Refactored data converters in fetch to improve performance
    - Fixed timestamp format FF to honor the scale of data type
    - Improved the security of OKTA authentication with hostname verifications
    - Retry PUT on the error ``OpenSSL.SSL.SysCallError`` 10053 with lower concurrency
    - Added ``raw_msg`` attribute to ``Error`` class
    - Refactored session managements

- v1.3.14 (February 24, 2017)

    - Improved PUT and GET error handler.
    - Added proxy support to OCSP checks.
    - Use proxy parameters for PUT and GET commands.
    - Added ``sfqid`` and ``sqlstate`` to the results from query results.
    - Fixed the connection timeout calculation based on ``login_timeout`` and ``network_timeout``.
    - Improved error messages in case of 403, 502 and 504 HTTP reponse code.
    - Upgraded ``cryptography`` to 1.7.2, ``boto3`` to 1.4.4 and ``botocore`` to 1.5.14.
    - Removed explicit DNS lookup for OCSP URL.

- v1.3.13 (February 9, 2017)

    - Fixed AWS SQS connection error with OCSP checks
    - Added ``login_timeout`` and ``network_timeout`` parameters to the ``Connection`` objects.
    - Fixed forbidden access error handing

- v1.3.12 (February 2, 2017)

    - Fixed ``region`` parameter. One character was truncated from the tail of account name
    - Improved performance of fetching data by refactoring fetchone method

- v1.3.11 (January 27, 2017)

    - Fixed the regression in 1.3.8 that caused intermittent 504 errors

- v1.3.10 (January 26, 2017)

    - Compress data in HTTP requests at all times except empty data or OKTA request
    - Refactored FIXED, REAL and TIMESTAMP data fetch to improve performance. This mainly impacts SnowSQL
    - Added ``region`` option to support EU deployments better
    - Increased the retry counter for OCSP servers to mitigate intermittent failure
    - Refactored HTTP access retry logic

- v1.3.9 (January 16, 2017)

    - Upgraded ``botocore`` to 1.4.93 to fix and ``boto3`` to 1.4.3 to fix the HTTPS request failure in Python 3.6
    - Fixed python2 incomaptible import http.client
    - Retry OCSP validation in case of non-200 HTTP code returned

- v1.3.8 (January 12, 2017)

    - Convert non-UTF-8 data in the large result set chunk to Unicode replacement characters to avoid decode error.
    - Updated copyright year to 2017.
    - Use `six` package to support both PY2 and PY3 for some functions
    - Upgraded ``cryptography`` to 1.7.1 to address MacOS Python 3.6 build issue.
    - Fixed OverflowError caused by invalid range of timetamp data for SnowSQL.

- v1.3.7 (December 8, 2016)

    - Increased the validity date acceptance window to prevent OCSP returning invalid responses due to out-of-scope validity dates for certificates.
    - Enabled OCSP response cache file by default.

- v1.3.6 (December 1, 2016)

    - Upgraded ``cryptography`` to 1.5.3, ``pyOpenSSL`` to 16.2.0 and ``cffi`` to 1.9.1.

- v1.3.5 (November 17, 2016)

    - Fixed CA list cache race condition
    - Added retry intermittent 400 HTTP ``Bad Request`` error

- v1.3.4 (November 3, 2016)

    - Added ``quoted_name`` data type support for binding by SQLAlchemy
    - Not to compress ``parquiet`` file in PUT command

- v1.3.3 (October 20, 2016)

    - Downgraded ``botocore`` to 1.4.37 due to potential regression.
    - Increased the stability of PUT and GET commands

- v1.3.2 (October 12, 2016)

    - Upgraded ``botocore`` to 1.4.52.
    - Set the signature version to v4 to AWS client. This impacts ``PUT``, ``GET`` commands and fetching large result set.

- v1.3.1 (September 30, 2016)

    - Added an account name including subdomain.

- v1.3.0 (September 26, 2016)

    - Added support for the ``BINARY`` data type, which enables support for more Python data types:

        - Python 3: 

            - ``bytes`` and ``bytearray`` can be used for binding.
            - ``bytes`` is also used for fetching ``BINARY`` data type.

        - Python 2:

            - ``bytearray`` can be used for binding
            - ``str`` is used for fetching ``BINARY`` data type.

    - Added ``proxy_user`` and ``proxy_password`` connection parameters for proxy servers that require authentication.

- v1.2.8 (August 16, 2016)

    - Upgraded ``botocore`` to 1.4.37.
    - Added ``Connection.execute_string`` and ``Connection.execute_stream`` to run multiple statements in a string and stream.
    - Increased the stability of fetching data for Python 2.
    - Refactored memory usage in fetching large result set (Work in Progress).

- v1.2.7 (July 31, 2016)

    - Fixed ``snowflake.cursor.rowcount`` for INSERT ALL.
    - Force OCSP cache invalidation after 24 hours for better security.
    - Use ``use_accelerate_endpoint`` in PUT and GET if Transfer acceleration is enabled for the S3 bucket.
    - Fixed the side effect of ``python-future`` that loads ``test.py`` in the current directory.

- v1.2.6 (July 13, 2016)

    - Fixed the AWS token renewal issue with PUT command when uploading uncompressed large files.

- v1.2.5 (July 8, 2016)

    - Added retry for errors ``S3UploadFailedError`` and ``RetriesExceededError`` in PUT and GET, respectively.

- v1.2.4 (July 6, 2016)

    - Added ``max_connection_pool`` parameter to Connection so that you can specify the maximum number of HTTP/HTTPS connections in the pool.
    - Minor enhancements for SnowSQL.

- v1.2.3 (June 29, 2016)

    - Fixed 404 issue in GET command. An extra slash character changed the S3 path and failed to identify the file to download.

- v1.2.2 (June 21, 2016)

    - Upgraded ``botocore`` to 1.4.26.
    - Added retry for 403 error when accessing S3.

- v1.2.1 (June 13, 2016)

    - Improved fetch performance for data types (part 2): DATE, TIME, TIMESTAMP, TIMESTAMP_LTZ, TIMESTAMP_NTZ and TIMESTAMP_TZ.

- v1.2.0 (June 10, 2016)

    - Improved fetch performance for data types (part 1): FIXED, REAL, STRING.

- v1.1.5 (June 2, 2016)

    - Upgraded ``boto3`` to 1.3.1 and ``botocore`` and 1.4.22.
    - Fixed ``snowflake.cursor.rowcount`` for DML by ``snowflake.cursor.executemany``.
    - Added ``numpy`` data type binding support. ``numpy.intN``, ``numpy.floatN`` and ``numpy.datetime64`` can be bound and fetched.

- v1.1.4 (May 21, 2016)

    - Upgraded ``cffi`` to 1.6.0.
    - Minor enhancements to SnowSQL.

- v1.1.3 (May 5, 2016)

    - Upgraded ``cryptography`` to 1.3.2.

- v1.1.2 (May 4, 2016)

    - Changed the dependency of ``tzlocal`` optional.
    - Fixed charmap error in OCSP checks.

- v1.1.1 (Apr 11, 2016)

    - Fixed OCSP revocation check issue with the new certificate and AWS S3.
    - Upgraded ``cryptography`` to 1.3.1 and ``pyOpenSSL`` to 16.0.0.

- v1.1.0 (Apr 4, 2016)

    - Added ``bzip2`` support in ``PUT`` command. This feature requires a server upgrade.
    - Replaced the self contained packages in ``snowflake._vendor`` with the dependency of ``boto3`` 1.3.0 and ``botocore`` 1.4.2.

- v1.0.7 (Mar 21, 2016)

    - Keep ``pyOpenSSL`` at 0.15.1.

- v1.0.6 (Mar 15, 2016)

    - Upgraded ``cryptography`` to 1.2.3.
    - Added support for ``TIME`` data type, which is now a Snowflake supported data type. This feature requires a server upgrade.
    - Added ``snowflake.connector.DistCursor`` to fetch the results in ``dict`` instead of ``tuple``.
    - Added compression to the SQL text and commands.

- v1.0.5 (Mar 1, 2016)

    - Upgraded ``cryptography`` to 1.2.2 and ``cffi`` to 1.5.2.
    - Fixed the conversion from ``TIMESTAMP_LTZ`` to datetime in queries.

- v1.0.4 (Feb 15, 2016)

    - Fixed the truncated parallel large result set.
    - Added retry OpenSSL low level errors ``ETIMEDOUT`` and ``ECONNRESET``.
    - Time out all HTTPS requests so that the Python Connector can retry the job or recheck the status.
    - Fixed the location of encrypted data for ``PUT`` command. They used to be in the same directory as the source data files.
    - Added support for renewing the AWS token used in ``PUT`` commands if the token expires.

- v1.0.3 (Jan 13, 2016)

    - Added support for the ``BOOLEAN`` data type (i.e. ``TRUE`` or ``FALSE``). This changes the behavior of the binding for the ``bool`` type object:
     
        - Previously, ``bool`` was bound as a numeric value (i.e. ``1`` for ``True``, ``0`` for ``False``).
        - Now, ``bool`` is bound as native SQL data (i.e. ``TRUE`` or ``FALSE``).

    - Added the ``autocommit`` method to the ``Connection`` object:
     
        - By default, ``autocommit`` mode is ON (i.e. each DML statement commits the change).
        - If ``autocommit`` mode is OFF, the ``commit`` and ``rollback`` methods are enabled.

    - Avoid segfault issue for ``cryptography`` 1.2 in Mac OSX by using 1.1 until resolved.

- v1.0.2 (Dec 15, 2015)

    - Upgraded ``boto3`` 1.2.2, ``botocore`` 1.3.12.
    - Removed ``SSLv3`` mapping from the initial table.

- v1.0.1 (Dec 8, 2015)

    - Minor bug fixes.

- v1.0.0 (Dec 1, 2015)

    - General Availability release.

