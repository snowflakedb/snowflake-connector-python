#!/usr/bin/env python
#
# Set a complex password for test user snowman
#
import os
import sys

from jenkins_test_parameters import SNOWFLAKE_TEST_PASSWORD_NEW

import snowflake.connector
from parameters import CONNECTION_PARAMETERS

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test'))

params = {
    'account': '<account_name>',
    'user': '<user_name>',
    'password': '<password>',
    'database': '<database_name>',
    'schema': '<schema_name>',
    'protocol': 'https',
    'host': '<host>',
    'port': '443',
}

# do we need to set time zone?
# import time
# os.environ['TZ'] = 'UTC'
# if not IS_WINDOWS:
#     time.tzset()

for k, v in CONNECTION_PARAMETERS.items():
    params[k] = v

conn = snowflake.connector.connect(**params)
conn.cursor().execute("use role accountadmin")
cmd = "alter user set password = '{}'".format(SNOWFLAKE_TEST_PASSWORD_NEW)
print(cmd)
conn.cursor().execute(cmd)
conn.close()

# generate ssm file
with open(os.getenv('CLIENT_KNOWN_SSM_FILE_PATH_DOCKER'), 'w') as f:
    f.write(SNOWFLAKE_TEST_PASSWORD_NEW + '\n')
