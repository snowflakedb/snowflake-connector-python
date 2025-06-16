import csv
import os
import random
import sys
from faker import Faker
from probes.logging_config import initialize_logger
from probes.login import connect
from probes.registry import prober_function  # noqa

import snowflake.connector
from snowflake.connector.util_text import random_string

# Initialize logger
logger = initialize_logger(__name__)


def generate_random_data(num_records: int, file_path: str) -> str:
    """
    Generates random CSV data with the specified number of rows.

    Args:
        num_records (int): Number of rows to generate.
        file_path (str): Path to save the generated CSV file.

    Returns:
        str: File path to CSV file
    """
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        fake = Faker()
        with open(file_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            writer.writerow(["id", "name", "email", "address"])
            for i in range(1, num_records + 1):
                writer.writerow([i, fake.name(), fake.email(), fake.address()])
        with open(file_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            rows = list(reader)
            # Subtract 1 for the header row
            actual_records = len(rows) - 1
            assert actual_records == num_records, logger.error(
                f"Expected {num_records} records, but found {actual_records}."
            )
        return file_path
    except Exception as e:
        logger.error(f"Error generating random data: {e}")
        sys.exit(1)

def get_python_version() ->str:
    """
    Returns the Python version being used.

    Returns:
        str: The Python version in the format 'major.minor'.
    """
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def get_driver_version() -> str:
    """
    Returns the version of the Snowflake connector.

    Returns:
        str: The version of the Snowflake connector.
    """
    return snowflake.connector.__version__

def setup_schema(cursor: snowflake.connector.cursor.SnowflakeCursor):
    """
    Sets up the schema in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    try:
        schema_name = random_string(10, "test_schema_")
        cursor.execute(f"CREATE OR REPLACE SCHEMA {schema_name};")
        cursor.execute(f"USE SCHEMA {schema_name}")
        if cursor.fetchone():
            print(
                f"cloudprober_driver_python_create_schema{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        return schema_name
    except Exception as e:
        logger.error(f"Error creating schema: {e}")
        print(
            f"cloudprober_driver_python_create_schema{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def setup_database(cursor: snowflake.connector.cursor.SnowflakeCursor):
    """
    Sets up the database in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    try:
        database_name = random_string(10, "test_database_")
        cursor.execute(f"CREATE OR REPLACE DATABASE {database_name};")

        cursor.execute(f"USE DATABASE {database_name};")
        if cursor.fetchone():
            print(
                f"cloudprober_driver_python_create_database{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        return database_name
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        print(
            f"cloudprober_driver_python_create_database{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)

def setup_warehouse(cursor: snowflake.connector.cursor.SnowflakeCursor, warehouse_name: str):
    """
    Sets up the warehouse in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        warehouse_name (str): The name of the warehouse to set up.
    """
    try:
        # Create or use the specified warehouse
        cursor.execute(f"CREATE WAREHOUSE IF NOT EXISTS {warehouse_name} WAREHOUSE_SIZE='X-SMALL';")
        cursor.execute(f"USE WAREHOUSE {warehouse_name};")
        print(
            f"cloudprober_driver_python_setup_warehouse{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
        )
    except Exception as e:
        logger.error(f"Error setup warehouse: {e}")
        print(
            f"cloudprober_driver_python_setup_warehouse{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)

def create_data_table(cursor: snowflake.connector.cursor.SnowflakeCursor) -> str:
    """
    Creates a data table in Snowflake with the specified schema.

    Returns:
        str: The name of the created table.
    """
    try:
        table_name = random_string(7, "test_data_")
        create_table_query = f"""
        CREATE OR REPLACE TABLE {table_name} (
            id INT,
            name STRING,
            email STRING,
            address STRING
        );
        """
        cursor.execute(create_table_query)
        if cursor.fetchone():
            print(
                f"cloudprober_driver_python_create_table{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
            # cursor.execute(f"USE TABLE {table_name};")
        else:
            print(
                f"cloudprober_driver_python_create_table{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error creating table: {e}")
        print(
            f"cloudprober_driver_python_create_table{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)
    return table_name


def create_data_stage(cursor: snowflake.connector.cursor.SnowflakeCursor) -> str:
    """
    Creates a stage in Snowflake for data upload.

    Returns:
        str: The name of the created stage.
    """
    try:
        stage_name = random_string(7, "test_data_stage_")
        create_stage_query = f"CREATE OR REPLACE STAGE {stage_name};"

        cursor.execute(create_stage_query)
        if cursor.fetchone():
            print(
                f"cloudprober_driver_python_create_stage{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"cloudprober_driver_python_create_stage{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
        return stage_name
    except Exception as e:
        print(
            f"cloudprober_driver_python_create_stage{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        logger.error(f"Error creating stage: {e}")
        sys.exit(1)


def copy_into_table_from_stage(
    table_name: str, stage_name: str, cur: snowflake.connector.cursor.SnowflakeCursor
):
    """
    Copies data from a stage into a specified table in Snowflake.

    Args:
        table_name (str): The name of the table where data will be copied.
        stage_name (str): The name of the stage from which data will be copied.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    try:
        cur.execute(
            f"""
                        COPY INTO {table_name}
                        FROM @{stage_name}
                        FILE_FORMAT = (TYPE = CSV FIELD_OPTIONALLY_ENCLOSED_BY = '"' SKIP_HEADER = 1);"""
        )

        # Check if the data was loaded successfully
        if cur.fetchall()[0][1] == "LOADED":
            print(
                f"cloudprober_driver_python_create_stage{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"cloudprober_driver_python_copy_data_from_stage_into_table{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error copying data from stage to table: {e}")
        print(
            f"cloudprober_driver_python_copy_data_from_stage_into_table{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def put_file_to_stage(
    file_name: str, stage_name: str, cur: snowflake.connector.cursor.SnowflakeCursor
):
    """
    Uploads a file to a specified stage in Snowflake.

    Args:
        file_name (str): The name of the file to upload.
        stage_name (str): The name of the stage where the file will be uploaded.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    try:
        response = cur.execute(
            f"PUT file://{file_name} @{stage_name} AUTO_COMPRESS=TRUE"
        ).fetchall()
        logger.error(response)

        if response[0][6] == "UPLOADED":
            print(
                f"cloudprober_driver_python_perform_put{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"cloudprober_driver_python_perform_put{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error uploading file to stage: {e}")
        print(
            f"cloudprober_driver_python_perform_put{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def count_data_from_table(
    table_name: str, num_records: int, cur: snowflake.connector.cursor.SnowflakeCursor
):
    try:
        count = cur.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        if count == num_records:
            print(
                f"cloudprober_driver_python_data_transferred_completely{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"cloudprober_driver_python_data_transferred_completely{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error counting data from table: {e}")
        print(
            f"cloudprober_driver_python_data_transferred_completely{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def compare_fetched_data(
    table_name: str,
    file_name: str,
    cur: snowflake.connector.cursor.SnowflakeCursor,
    repetitions: int = 10,
    fetch_limit: int = 100,
):
    """
    Compares the data fetched from the table with the data in the CSV file.

    Args:
        table_name (str): The name of the table to fetch data from.
        file_name (str): The name of the CSV file to compare data against.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        repetitions (int): Number of times to repeat the comparison. Default is 10.
        fetch_limit (int): Number of rows to fetch from the table for comparison. Default is 100.
    """
    try:
        fetched_data = cur.execute(
            f"SELECT * FROM {table_name} LIMIT {fetch_limit}"
        ).fetchall()

        with open(file_name, newline="", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            csv_data = list(reader)[1:]  # Skip header row
            for _ in range(repetitions):
                random_index = random.randint(0, fetch_limit - 1)
                for y in range(len(fetched_data[0])):
                    if str(fetched_data[random_index][y]) != csv_data[random_index][y]:
                        print(
                            f"cloudprober_driver_python_data_transferred_completely{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
                        )
                        sys.exit(1)
            print(
                f"cloudprober_driver_python_data_data_integrity{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
    except Exception as e:
        logger.error(f"Error comparing fetched data: {e}")
        print(
            f"cloudprober_driver_python_data_data_integrity{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def execute_get_command(stage_name: str, conn: snowflake.connector.SnowflakeConnection):
    """
    Downloads a file from a specified stage in Snowflake.

    Args:
        stage_name (str): The name of the stage from which the file will be downloaded.
        conn (snowflake.connector.SnowflakeConnection): The connection object to execute the SQL command.
    """
    download_dir = f"/tmp/{conn.account}/{stage_name}"

    try:
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
        conn.cursor().execute(f"GET @{stage_name} file://{download_dir}/ ;")
        # Check if files are downloaded
        downloaded_files = os.listdir(download_dir)
        if downloaded_files:
            print(
                f"cloudprober_driver_python_perform_get{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )

        else:
            print(
                f"cloudprober_driver_python_perform_get{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error downloading file from stage: {e}")
        print(
            f"cloudprober_driver_python_perform_get{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)
    finally:
        try:
            for file in os.listdir(download_dir):
                file_path = os.path.join(download_dir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            os.rmdir(download_dir)
        except FileNotFoundError:
            logger.error(
                f"Error cleaning up directory {download_dir}. It may not exist or be empty."
            )
            sys.exit(1)


def perform_put_fetch_get(connection_parameters: dict, num_records: int = 1000):
    """
    Performs a PUT, fetch and GET operation using the provided connection parameters.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.
        num_records (int): Number of records to generate and PUT. Default is 10,000.
    """
    try:
        with connect(connection_parameters) as conn:
            with conn.cursor() as cur:

                logger.error("Setting up database")
                database_name = setup_database(cur)
                logger.error("Database setup complete")

                logger.error("Setting up schema")
                schema_name = setup_schema(cur)
                logger.error("Schema setup complete")

                logger.error("Setting up warehouse")
                setup_warehouse(cur, conn.warehouse)

                logger.error("Creating stage")
                stage_name = create_data_stage(cur)
                logger.error(f"Stage {stage_name} created")

                logger.error("Creating table")
                table_name = create_data_table(cur)
                logger.error(f"Table {table_name} created")

                logger.error("Generating random data")

                file_name = generate_random_data(num_records, f"/tmp/{table_name}.csv")

                logger.error(f"Random data generated in {file_name}")

                logger.error("PUT file to stage")
                put_file_to_stage(file_name, stage_name, cur)
                logger.error(f"File {file_name} uploaded to stage {stage_name}")

                logger.error("Copying data from stage to table")
                copy_into_table_from_stage(table_name, stage_name, cur)
                logger.error(
                    f"Data copied from stage {stage_name} to table {table_name}"
                )

                logger.error("Counting data in the table")
                count_data_from_table(table_name, num_records, cur)

                logger.error("Comparing fetched data with CSV file")
                compare_fetched_data(table_name, file_name, cur)

                logger.error("Performing GET operation")
                execute_get_command(stage_name, conn)
                logger.error("File downloaded from stage to local directory")
                sys.exit(0)

    except Exception as e:
        logger.error(f"Error during PUT_FETCH_GET operation: {e}")

    finally:
        try:
        # Cleanup: Remove data from the stage and delete table
            logger.error("Cleaning up resources")

            with connect(connection_parameters) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"USE DATABASE {database_name}")
                    cur.execute(f"USE SCHEMA {schema_name}")
                    cur.execute(f"REMOVE @{stage_name}")
                    cur.execute(f"DROP TABLE {table_name}")
                    cur.execute(f"DROP DATABASE {database_name}")
            logger.error("Resources cleaned up successfully")
            print(
                f"cloudprober_driver_python_cleanup_resources{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            print(
                f"cloudprober_driver_python_cleanup_resources{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)


@prober_function
def perform_put_fetch_get_100_lines(connection_parameters: dict):
    """
    Performs a PUT and GET operation for 1,000 rows using the provided connection parameters.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.
    """
    perform_put_fetch_get(connection_parameters, num_records=100)
