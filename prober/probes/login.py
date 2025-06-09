import sys

from probes.logging_config import initialize_logger
from probes.registry import prober_function

import snowflake.connector

# Initialize logger
logger = initialize_logger(__name__)


def connect(connection_parameters: dict):
    """
    Initializes the Python driver for login using the provided connection parameters.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.

    Returns:
        snowflake.connector.SnowflakeConnection: A connection object if successful.
    """
    try:
        # Initialize the Snowflake connection
        connection = snowflake.connector.connect(
            user=connection_parameters["user"],
            account=connection_parameters["account"],
            host=connection_parameters["host"],
            port=connection_parameters["port"],
            warehouse=connection_parameters["warehouse"],
            database=connection_parameters["database"],
            schema=connection_parameters["schema"],
            role=connection_parameters["role"],
            authenticator=connection_parameters["authenticator"],
            private_key_file=connection_parameters["private_key_file"],
        )
        return connection
    except Exception as e:
        logger.info({f"success_login={False}"})
        logger.error(f"Error connecting to Snowflake: {e}")


@prober_function
def perform_login(connection_parameters: dict):
    """
    Performs the login operation using the provided connection parameters.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    try:
        # Connect to Snowflake
        connection = connect(connection_parameters)

        # Log the connection details
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        driver_version = snowflake.connector.__version__

        # Perform a simple query to test the connection
        cursor = connection.cursor()
        cursor.execute("SELECT 1;")
        result = cursor.fetchone()
        logger.error(f"Logging: {result}")
        assert result == (1,)
        print(f"cloudprober_driver_python_perform_login{{python_version={python_version}, driver_version={driver_version}}} 0")
    except Exception as e:
        print(f"cloudprober_driver_python_perform_login{{python_version={python_version}, driver_version={driver_version}}} 1")
        logger.error(f"Error during login: {e}")
