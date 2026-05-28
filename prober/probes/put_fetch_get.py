import csv
import os
import random
import re
import sys

from faker import Faker
from probes.logging_config import initialize_logger
from probes.login import connect
from probes.registry import prober_function

import snowflake.connector

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


def get_python_version() -> str:
    """
    Returns the Python version being used.

    Prefers the value pinned by the deployment via the PROBER_PYTHON_VERSION
    environment variable (set by entrypoint.sh from the testing matrix) so
    that resource names and metric labels match the deployment matrix
    exactly (e.g. "3.13.4"). Falls back to runtime introspection
    (major.minor only) when the variable is not set.

    Returns:
        str: The Python version string.
    """
    return (
        os.environ.get("PROBER_PYTHON_VERSION")
        or f"{sys.version_info.major}.{sys.version_info.minor}"
    )


def get_driver_version() -> str:
    """
    Returns the version of the Snowflake connector.

    Prefers the value pinned by the deployment via the PROBER_DRIVER_VERSION
    environment variable (set by entrypoint.sh from the testing matrix).
    Falls back to the installed package version when the variable is not set.

    Returns:
        str: The connector version string.
    """
    return (
        os.environ.get("PROBER_DRIVER_VERSION") or snowflake.connector.__version__
    )


def _sanitize_identifier_part(value: str) -> str:
    """
    Converts a free-form string (e.g. "3.15.0.dev0+abc") into a fragment that
    is safe to embed in an unquoted Snowflake identifier.
    """
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


def get_resource_suffix(name_suffix: str = "") -> str:
    """
    Builds a deterministic suffix from the Python and driver versions so that
    each (language, driver_version[, probe_variant]) combination owns a stable
    pool of Snowflake object names.

    Using a deterministic name (instead of a random one) bounds the number of
    stages/tables a prober can leak: if cleanup is skipped on crash, the next
    run with the same versions reuses the same name and `CREATE OR REPLACE`
    wipes the leftover state.

    Args:
        name_suffix: Optional discriminator (e.g. "fail_closed") to keep
            different probe variants from colliding with each other when they
            run against the same schema.
    """
    parts = [
        f"py{_sanitize_identifier_part(get_python_version())}",
        f"drv{_sanitize_identifier_part(get_driver_version())}",
    ]
    if name_suffix:
        parts.append(_sanitize_identifier_part(name_suffix))
    return "_".join(parts)


def setup_schema(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    schema_name: str,
    metric_name: str = "cloudprober_driver_python_create_schema",
):
    """
    Sets up the schema in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        schema_name (str): The name of the schema to set up.
    """
    try:
        cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name};")
        cursor.execute(f"USE SCHEMA {schema_name}")
        if cursor.fetchone():
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        return schema_name
    except Exception as e:
        logger.error(f"Error creating schema: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def setup_database(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    database_name: str,
    metric_name: str = "cloudprober_driver_python_create_database",
):
    """
    Sets up the database in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        database_name (str): The name of the database to set up.
    """
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name};")
        cursor.execute(f"USE DATABASE {database_name};")
        if cursor.fetchone():
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        return database_name
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def setup_warehouse(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    warehouse_name: str,
    metric_name: str = "cloudprober_driver_python_setup_warehouse",
):
    """
    Sets up the warehouse in Snowflake.

    Args:
        cursor (snowflake.connector.cursor.SnowflakeCursor): The cursor to execute the SQL command.
        warehouse_name (str): The name of the warehouse to set up.
    """
    try:
        cursor.execute(
            f"CREATE WAREHOUSE IF NOT EXISTS {warehouse_name} WAREHOUSE_SIZE='X-SMALL';"
        )
        cursor.execute(f"USE WAREHOUSE {warehouse_name};")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
        )
    except Exception as e:
        logger.error(f"Error setup warehouse: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def create_data_table(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_create_table",
    name_suffix: str = "",
) -> str:
    """
    Creates a data table in Snowflake with the specified schema.

    The table name is deterministic per (python_version, driver_version,
    name_suffix) so that leaked tables from previously aborted runs are
    overwritten via CREATE OR REPLACECREATE OR REPLACE on the next run instead of accumulating.

    Returns:
        str: The name of the created table.
    """
    try:
        table_name = f"test_data_{get_resource_suffix(name_suffix)}"
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
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
            # cursor.execute(f"USE TABLE {table_name};")
        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error creating table: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)
    return table_name


def create_data_stage(
    cursor: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_create_stage",
    name_suffix: str = "",
) -> str:
    """
    Creates a stage in Snowflake for data upload.

    The stage name is deterministic per (python_version, driver_version,
    name_suffix) so that leaked stages from previously aborted runs are
    overwritten via CREATE OR REPLACE on the next run instead of accumulating.

    Returns:
        str: The name of the created stage.
    """
    try:
        stage_name = f"test_data_stage_{get_resource_suffix(name_suffix)}"
        create_stage_query = f"CREATE OR REPLACE STAGE {stage_name};"

        cursor.execute(create_stage_query)
        if cursor.fetchone():
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
        return stage_name
    except Exception as e:
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        logger.error(f"Error creating stage: {e}")
        sys.exit(1)


# Legacy random-suffix naming used by previous prober deployments.
#
# Two suffix lengths were used historically (verified from git history):
#   - 7 lowercase ASCII letters  (earliest version)
#   - 10 lowercase ASCII letters (later version)
#
# Both used `snowflake.connector.util_text.random_string` with the default
# `choices=string.ascii_lowercase`, so the suffix character class is strictly
# [a-z] with no digits, dashes, or underscores. Snowflake stores unquoted
# identifiers in UPPERCASE, so INFORMATION_SCHEMA returns [A-Z] -- the regex
# below matches that form directly.
#
# The current naming scheme always contains digits (from the version numbers,
# e.g. "py3_13_4_drv3_15_0"), so a name matching `[A-Z]{7,10}` after the prefix
# is unambiguously a legacy leftover and safe to drop.
_LEGACY_STAGE_REGEX = r"^TEST_DATA_STAGE_[A-Z]{7,10}$"
_LEGACY_TABLE_REGEX = r"^TEST_DATA_[A-Z]{7,10}$"

# Per-invocation drop budget. Operators can raise this during a dedicated
# cleanup window (e.g. to chew through millions of leaked objects) without
# code changes by setting PROBER_LEGACY_CLEANUP_BATCH_SIZE in the environment.
# Capped well below `SHOW`'s 10 000 default so the work stays fast and
# predictable even for the largest backlog.
_DEFAULT_LEGACY_CLEANUP_BATCH_SIZE = 1000


def _legacy_cleanup_batch_size() -> int:
    raw = os.environ.get("PROBER_LEGACY_CLEANUP_BATCH_SIZE")
    if not raw:
        return _DEFAULT_LEGACY_CLEANUP_BATCH_SIZE
    try:
        value = int(raw)
        return value if value > 0 else _DEFAULT_LEGACY_CLEANUP_BATCH_SIZE
    except ValueError:
        return _DEFAULT_LEGACY_CLEANUP_BATCH_SIZE


def _drop_legacy_objects_in_batch(
    cur: snowflake.connector.cursor.SnowflakeCursor,
    info_schema_view: str,
    name_column: str,
    catalog_column: str,
    schema_column: str,
    drop_kind: str,
    name_regex: str,
    batch_size: int,
) -> int:
    """
    Server-side, single-round-trip cleanup of one object kind.

    Runs a Snowflake Scripting block that:
      1. Selects up to `batch_size` object names from INFORMATION_SCHEMA
         matching the legacy regex (filter pushed down to Snowflake).
      2. Loops in-database and issues `DROP <kind> IF EXISTS` for each.
      3. Returns the count of objects dropped in this batch.

    This avoids returning millions of names to the client and avoids one
    network round-trip per drop -- critical when the leak is in the millions.
    """
    script = f"""
EXECUTE IMMEDIATE $$
DECLARE
    dropped INT DEFAULT 0;
    rs RESULTSET DEFAULT (
        SELECT {name_column} AS object_name
        FROM INFORMATION_SCHEMA.{info_schema_view}
        WHERE {catalog_column} = CURRENT_DATABASE()
          AND {schema_column} = CURRENT_SCHEMA()
          AND REGEXP_LIKE({name_column}, '{name_regex}')
        LIMIT {batch_size}
    );
BEGIN
    LET c1 CURSOR FOR rs;
    FOR row_var IN c1 DO
        EXECUTE IMMEDIATE 'DROP {drop_kind} IF EXISTS "' || row_var.object_name || '"';
        dropped := dropped + 1;
    END FOR;
    RETURN dropped;
END;
$$
"""
    result = cur.execute(script).fetchone()
    return int(result[0]) if result and result[0] is not None else 0


def cleanup_legacy_random_resources(
    cur: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_cleanup_legacy_resources",
) -> None:
    """
    Drops a bounded batch of stages and tables left behind by previous prober
    deployments that used a random 7-or-10 lowercase suffix.

    Designed for very large backlogs (millions of objects):
      - The match filter and the DROP loop both run server-side in a single
        Snowflake Scripting block per object kind (two round-trips total,
        regardless of backlog size).
      - Each invocation drops at most PROBER_LEGACY_CLEANUP_BATCH_SIZE
        objects of each kind, so a single probe run is bounded in latency.
      - Repeated invocations drain the backlog incrementally; once empty,
        the queries are effectively no-ops.

    Best-effort: never raises -- a cleanup failure must not flip the main
    probe outcome.
    """
    try:
        batch_size = _legacy_cleanup_batch_size()
        stages_dropped = _drop_legacy_objects_in_batch(
            cur,
            info_schema_view="STAGES",
            name_column="stage_name",
            catalog_column="stage_catalog",
            schema_column="stage_schema",
            drop_kind="STAGE",
            name_regex=_LEGACY_STAGE_REGEX,
            batch_size=batch_size,
        )
        tables_dropped = _drop_legacy_objects_in_batch(
            cur,
            info_schema_view="TABLES",
            name_column="table_name",
            catalog_column="table_catalog",
            schema_column="table_schema",
            drop_kind="TABLE",
            name_regex=_LEGACY_TABLE_REGEX,
            batch_size=batch_size,
        )
        logger.error(
            f"Legacy cleanup batch: dropped {stages_dropped} stages and "
            f"{tables_dropped} tables (batch_size={batch_size})"
        )
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
        )
    except Exception as e:
        logger.error(f"Error during legacy resource cleanup: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )


def copy_into_table_from_stage(
    table_name: str,
    stage_name: str,
    cur: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_copy_data_from_stage_into_table",
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
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error copying data from stage to table: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def put_file_to_stage(
    file_name: str,
    stage_name: str,
    cur: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_perform_put",
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
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error uploading file to stage: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def count_data_from_table(
    table_name: str,
    num_records: int,
    cur: snowflake.connector.cursor.SnowflakeCursor,
    metric_name: str = "cloudprober_driver_python_data_transferred_completely",
):
    try:
        count = cur.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        if count == num_records:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error counting data from table: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def compare_fetched_data(
    table_name: str,
    file_name: str,
    cur: snowflake.connector.cursor.SnowflakeCursor,
    repetitions: int = 10,
    fetch_limit: int = 100,
    metric_name: str = "cloudprober_driver_python_data_integrity",
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
                            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
                        )
                        sys.exit(1)
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )
    except Exception as e:
        logger.error(f"Error comparing fetched data: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
        )
        sys.exit(1)


def execute_get_command(
    stage_name: str,
    conn: snowflake.connector.SnowflakeConnection,
    metric_name: str = "cloudprober_driver_python_perform_get",
):
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
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 0"
            )

        else:
            print(
                f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
            )
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error downloading file from stage: {e}")
        print(
            f"{metric_name}{{python_version={get_python_version()}, driver_version={get_driver_version()}}} 1"
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
                database_name = setup_database(cur, conn.database)
                logger.error("Database setup complete")

                logger.error("Setting up schema")
                schema_name = setup_schema(cur, conn.schema)
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
                    cleanup_legacy_random_resources(cur)
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
