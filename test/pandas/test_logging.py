import logging
import snowflake.connector


def test_rand_table_log(caplog, db_parameters):
    # set up connection
    conn = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        database=db_parameters['database'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol']
    )

    logger = logging.getLogger('snowflake.connector')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(threadName)s `%(filename)s`:%(lineno)d '
                                      '- %(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

    # execute query and collect logs
    num_of_rows = 10
    with conn.cursor() as cur:
        cur.execute("select randstr(abs(mod(random(), 100)), random()) from table(generator(rowcount => {}));"
                    .format(num_of_rows)).fetchall()

    # make assertions
    has_batch_read = has_batch_size = has_chunk_info = has_batch_index = has_done = False
    for record in caplog.records:
        if "Batches read:" in record.msg:
            has_batch_read = True
            assert "arrow_iterator" in record.filename
            assert "__cinit__" in record.funcName

        if "Arrow BatchSize:" in record.msg:
            has_batch_size = True
            assert "CArrowIterator.cpp" in record.filename
            assert "CArrowIterator" in record.funcName

        if "Arrow chunk info:" in record.msg:
            has_chunk_info = True
            assert "CArrowChunkIterator.cpp" in record.filename
            assert "CArrowChunkIterator" in record.funcName

        if "Current batch index:" in record.msg:
            has_batch_index = True
            assert "CArrowChunkIterator.cpp" in record.filename
            assert "next" in record.funcName

        if "fetching data done" in record.msg:
            has_done = True
            assert "arrow_result" in record.filename  # using arrow result

    # each of these records appear at least once in records
    assert has_batch_read and has_batch_size and has_chunk_info and has_batch_index and has_done
