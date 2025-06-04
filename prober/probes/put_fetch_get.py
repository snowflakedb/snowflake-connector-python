import csv
import random

from probes.login import connect
from probes.logging_config import initialize_logger
from probes.registry import prober_function
from faker import Faker

import snowflake.connector
from snowflake.connector.util_text import random_string


# Initialize logger
logger = initialize_logger(__name__)

def generate_random_data(num_records: int, file_path: str) -> str:
    """
    Generates random CSV data with the specified number of rows.

    Args:
        num_records (int): Number of rows to generate.

    Returns:
        str: File path to CSV file
    """
    fake = Faker()
    with open(file_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow(['id', 'name', 'email', 'address'])
        for i in range(1, num_records + 1):
            writer.writerow([i, fake.name(), fake.email(), fake.address()])
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)
        # Subtract 1 for the header row
        actual_records = len(rows) - 1
        assert actual_records == num_records, logger.error(f"Expected {num_records} records, but found {actual_records}.")
    return file_path

def create_data_table(cursor: snowflake.connector.cursor.SnowflakeCursor) -> str:
    """
    Creates a data table in Snowflake with the specified schema.

    Returns:
        str: The name of the created table.
    """
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
        print({"successfully_created_table": True})
    else:
        print({"successfully_created_table": False})
    return table_name

def create_data_stage(cursor: snowflake.connector.cursor.SnowflakeCursor) -> str:
    """
    Creates a stage in Snowflake for data upload.

    Returns:
        str: The name of the created stage.
    """
    stage_name = random_string(7, "test_data_stage_")
    create_stage_query = f"CREATE OR REPLACE STAGE {stage_name};"

    cursor.execute(create_stage_query)
    if cursor.fetchone():
        print({"successfully_created_stage": True})
    else:
        print({"successfully_created_stage": False})
    return stage_name

def copy_into_table_from_stage(table_name: str, stage_name: str, cur: snowflake.connector.cursor.SnowflakeCursor):
    """
    Copies data from a stage into a specified table in Snowflake.

    Args:
        table_name (str): The name of the table where data will be copied.
        stage_name (str): The name of the stage from which data will be copied.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    cur.execute(
                    f"""
                    COPY INTO {table_name}
                    FROM @{stage_name}
                    FILE_FORMAT = (TYPE = CSV FIELD_OPTIONALLY_ENCLOSED_BY = '"' SKIP_HEADER = 1);""")

    # Check if the data was loaded successfully
    if cur.fetchall()[0][1] == 'LOADED':
        print({"successfully_copied_data": True})
    else:
        print({"successfully_copied_data": False})

def put_file_to_stage(file_name: str, stage_name: str, cur: snowflake.connector.cursor.SnowflakeCursor):
    """
    Uploads a file to a specified stage in Snowflake.

    Args:
        file_name (str): The name of the file to upload.
        stage_name (str): The name of the stage where the file will be uploaded.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
    """
    response = cur.execute(f"PUT file://{file_name} @{stage_name} AUTO_COMPRESS=TRUE").fetchall()
    logger.error(response)

    if response[0][6] == 'UPLOADED':
        print({"successfully_uploaded_file": True})
    else:
        print({"successfully_uploaded_file": False})

def count_data_from_table(table_name: str, num_records: int, cur: snowflake.connector.cursor.SnowflakeCursor):
    count = cur.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
    if count == num_records:
        print({"data_transferred_completely": True})
    else:
        print({"data_transferred_completely": False})

def compare_fetched_data(table_name: str, file_name: str, cur: snowflake.connector.cursor.SnowflakeCursor, repetitions: int = 10):
    """
    Compares the data fetched from the table with the data in the CSV file.

    Args:
        table_name (str): The name of the table to fetch data from.
        file_name (str): The name of the CSV file to compare data against.
        cur (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        repetitions (int): Number of times to repeat the comparison. Default is 10.
    """

    fetched_data = cur.execute(f"SELECT * FROM {table_name} LIMIT 100").fetchall()

    with open(file_name, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        csv_data = list(reader)[1:]  # Skip header row

        for x in range(repetitions):
            random_index = random.randint(0, len(csv_data) - 1)
            for y in range(len(fetched_data[0])):
                if str(fetched_data[random_index][y]) != csv_data[random_index][y]:
                    print({"data_integrity_check": False})
                    break
        print({"data_integrity_check": True})


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

                # Create a stage and table for data upload
                logger.error("Creating stage")
                stage_name = create_data_stage(cur)
                logger.error(f"Stage {stage_name} created")

                logger.error("Creating stage")
                table_name = create_data_table(cur)
                logger.error(f"Table {table_name} created")

                logger.error("Generating random data")
                file_name = generate_random_data(num_records, f"{table_name}.csv")
                logger.error(f"Random data generated in {file_name}")

                logger.error("PUT file to stage")
                put_file_to_stage(file_name, stage_name, cur)
                logger.error(f"File {file_name} uploaded to stage {stage_name}")

                logger.error("Copying data from stage to table")
                copy_into_table_from_stage(table_name, stage_name, cur)
                logger.error(f"Data copied from stage {stage_name} to table {table_name}")

                logger.error("Counting data in the table")
                count_data_from_table(table_name, num_records, cur)

                logger.error("Comparing fetched data with CSV file")
                compare_fetched_data(table_name, file_name, cur)

                # todo: add GET and checks

    except Exception as e:
        logger.error(f"Error during PUT/GET operation: {e}")

    finally:
        # Cleanup: Remove data from the stage and delete table
        with connect(connection_parameters) as conn:
            with conn.cursor() as cur:
                cur.execute(f"REMOVE @{stage_name}")
                cur.execute(f"DROP TABLE {table_name}")


@prober_function
def perform_put_fetch_get_100_lines(connection_parameters: dict):
    """
    Performs a PUT and GET operation for 1,000 rows using the provided connection parameters.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.
    """
    perform_put_fetch_get(connection_parameters, num_records=100)