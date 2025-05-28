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
            authenticator="KEY_PAIR_AUTHENTICATOR",
            private_key=connection_parameters["private_key"],
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

        # Perform a simple query to test the connection
        cursor = connection.cursor()
        cursor.execute("SELECT 1;")
        result = cursor.fetchone()
        logger.info(result)
        assert result == (1,)
        logger.info({f"success_login={True}"})
    except Exception as e:
        logger.info({f"success_login={False}"})
        logger.error(f"Error during login: {e}")
