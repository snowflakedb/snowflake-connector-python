#!/usr/bin/env python
#
# Set a complex password for test user snowman
#
import os
import sys

import snowflake.connector

sys.path.append(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test")
)

CLIENT_KNOWN_SSM_FILE_PATH_DOCKER = "CLIENT_KNOWN_SSM_FILE_PATH_DOCKER"


def change_password():
    params = {
        "account": "<account_name>",
        "user": "<user_name>",
        "password": "<password>",
        "database": "<database_name>",
        "schema": "<schema_name>",
        "protocol": "https",
        "host": "<host>",
        "port": "443",
    }

    for k, v in CONNECTION_PARAMETERS.items():
        params[k] = v

    conn = snowflake.connector.connect(**params)
    conn.cursor().execute("use role accountadmin")
    cmd = "alter user set password = '{}'".format(SNOWFLAKE_TEST_PASSWORD_NEW)
    print(cmd)
    conn.cursor().execute(cmd)
    conn.close()


def generate_known_ssm_file():
    with open(os.getenv(CLIENT_KNOWN_SSM_FILE_PATH_DOCKER), "w") as f:
        f.write(SNOWFLAKE_TEST_PASSWORD_NEW + "\n")


if __name__ == "__main__":
    from jenkins_test_parameters import SNOWFLAKE_TEST_PASSWORD_NEW

    from parameters import CONNECTION_PARAMETERS

    change_password()
    generate_known_ssm_file()
