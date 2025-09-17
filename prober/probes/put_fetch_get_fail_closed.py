from probes.put_fetch_get import *
from probes.logging_config import initialize_logger
from probes.login import connect
from probes.registry import prober_function

# Initialize logger
logger = initialize_logger(__name__)


def perform_put_fetch_get_fail_closed(connection_parameters: dict, num_records: int = 1000):
    """
    Performs a PUT, fetch and GET operation using the provided connection parameters under fail closed mode.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.
        num_records (int): Number of records to generate and PUT. Default is 1,000.
    """
    try:
        with connect(connection_parameters) as conn:
            with conn.cursor() as cur:

                logger.error("Setting up database")
                database_name = setup_database(cur, conn.database, "cloudprober_driver_python_create_database_fail_closed")
                logger.error("Database setup complete")

                logger.error("Setting up schema")
                schema_name = setup_schema(cur, conn.schema, "cloudprober_driver_python_create_schema_fail_closed")
                logger.error("Schema setup complete")

                logger.error("Setting up warehouse")
                setup_warehouse(cur, conn.warehouse, "cloudprober_driver_python_setup_warehouse_fail_closed")

                logger.error("Creating stage")
                stage_name = create_data_stage(cur, "cloudprober_driver_python_create_stage_fail_closed")
                logger.error(f"Stage {stage_name} created")

                logger.error("Creating table")
                table_name = create_data_table(cur, "cloudprober_driver_python_create_table_fail_closed")
                logger.error(f"Table {table_name} created")

                logger.error("Generating random data")

                file_name = generate_random_data(num_records, f"/tmp/{table_name}.csv", "cloudprober_driver_python_generate_random_data_fail_closed")

                logger.error(f"Random data generated in {file_name}")

                logger.error("PUT file to stage")
                put_file_to_stage(file_name, stage_name, cur, "cloudprober_driver_python_perform_put_fail_closed")
                logger.error(f"File {file_name} uploaded to stage {stage_name}")

                logger.error("Copying data from stage to table")
                copy_into_table_from_stage(table_name, stage_name, cur, "cloudprober_driver_python_copy_data_from_stage_into_table_fail_closed")
                logger.error(
                    f"Data copied from stage {stage_name} to table {table_name}"
                )

                logger.error("Counting data in the table")
                count_data_from_table(table_name, num_records, cur, "cloudprober_driver_python_data_transferred_completely_fail_closed")

                logger.error("Comparing fetched data with CSV file")
                compare_fetched_data(table_name, file_name, cur, "cloudprober_driver_python_data_integrity_fail_closed")   

                logger.error("Performing GET operation")
                execute_get_command(stage_name, conn, "cloudprober_driver_python_perform_get_fail_closed")
                logger.error("File downloaded from stage to local directory")

    except Exception as e:
        logger.error(f"Error during PUT_FETCH_GET operation: {e}")
        sys.exit(1)
    finally:
        try:
            logger.error("Cleaning up resources")
            with connect(connection_parameters) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"USE DATABASE {database_name}")
                    cur.execute(f"USE SCHEMA {schema_name}")
                    cur.execute(f"REMOVE @{stage_name}")
                    cur.execute(f"DROP TABLE {table_name}")
            logger.error("Resources cleaned up successfully")
            print(
                f"cloudprober_driver_python_cleanup_resources_fail_closed{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            print(
                f"cloudprober_driver_python_cleanup_resources_fail_closed{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)


@prober_function
def perform_put_fetch_get_100_lines_fail_closed(connection_parameters: dict):
    """
    Performs a PUT and GET operation for 100 rows using the provided connection parameters in fail_close mode.

    Args:
        connection_parameters (dict): A dictionary containing connection details such as
                                       host, port, user, password, account, schema, etc.
    """
    connection_parameters["ocsp_fail_open"] = False
    perform_put_fetch_get_fail_closed(connection_parameters, num_records=100)
