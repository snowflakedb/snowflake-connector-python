import threading

import snowflake.connector

# Number of threads
THREAD_COUNT = 80

# Create a barrier so all threads start at the same time
start_barrier = threading.Barrier(THREAD_COUNT)


def snowflake_task(results, index, db_parameters):
    try:
        # Wait for all threads to be ready
        start_barrier.wait()

        with snowflake.connector.connect(
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            warehouse=db_parameters.get("warehouse"),
            role=db_parameters.get("role"),
            schema=db_parameters.get("schema"),
            port=db_parameters["port"],
            database=db_parameters["database"],
            account=db_parameters["account"],
            protocol=db_parameters["protocol"],
        ) as conn:
            cs = conn.cursor()
            cs.execute("SELECT 1")
            result = cs.fetchone()[0]
            results[index] = result
            print(f"RESULT OF FETCH {index} ==== {result}")

    except Exception as e:
        results[index] = f"Error: {e}"
        print(f"THREAD {index} ERROR: {e}")


# Pytest test
def test_snowflake_threads(db_parameters):
    print("\n\nTesting snowflake threads\n\n")
    threads = []
    results = [None] * THREAD_COUNT

    for i in range(THREAD_COUNT):
        t = threading.Thread(target=snowflake_task, args=(results, i, db_parameters))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Validate all threads returned 1
    for result in results:
        assert result == 1, f"Thread failed with result: {result}"
