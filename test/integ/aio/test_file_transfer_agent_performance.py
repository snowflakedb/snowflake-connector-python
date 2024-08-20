#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
import csv
import gzip
import os.path
import shutil
from time import time

import pytest

pytestmark = pytest.mark.asyncio


def read_csv(file_path: str):
    with open(file_path) as f:
        reader = csv.reader(f)
        return list(reader)


def read_multiple_csv(file_path: str, file_name):
    files = sorted(os.listdir(file_path))
    res = []
    for file in files:
        if file.startswith(file_name):
            with open(os.path.join(file_path, file)) as f:
                reader = csv.reader(f)
                res.append(list(reader))
    return res


def unzip_file(file_path: str):
    new_file = file_path.replace(".gz", "")
    if file_path.endswith(".gz"):
        with gzip.open(file_path, "rb") as f_in:
            with open(new_file, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(file_path)


def unzip_multiple_files(file_path: str, file_name: str):
    files = os.listdir(file_path)
    for file in files:
        if file.startswith(file_name):
            if file.endswith(".gz"):
                old_file = os.path.join(file_path, file)
                new_file = os.path.join(file_path, file.replace(".gz", ""))
                with gzip.open(old_file, "rb") as f_in:
                    with open(new_file, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(old_file)


async def test_put_and_get_single_small_file(
    aio_connection, conn_cnx, db_parameters, tmpdir
):
    datadir = tmpdir.mkdir("test_put_and_get_single_small_file")
    data_dir = datadir.strpath
    target_file_name = "single_chunk_file.csv"
    with conn_cnx() as cnx:
        start = time()
        cnx.cursor().execute(
            f"GET @{db_parameters['database']}.PUBLIC.teststage_python/{target_file_name} file://{data_dir}"
        )
        end = time()
        sync_download_time = end - start
        unzip_file(os.path.join(data_dir, f"{target_file_name}.gz"))

        start = time()
        cnx.cursor().execute(
            f"PUT file://{os.path.join(data_dir, target_file_name)} @{db_parameters['database']}.PUBLIC.teststage_python OVERWRITE = TRUE"
        )
        end = time()
        sync_upload_time = end - start

    raw_content = read_csv(os.path.join(data_dir, target_file_name))

    await aio_connection.connect()
    cursor = aio_connection.cursor()
    start = time()
    await cursor.execute(
        f"PUT file://{os.path.join(data_dir, target_file_name)} @{db_parameters['database']}.PUBLIC.teststage_python OVERWRITE = TRUE"
    )
    end = time()
    async_upload_time = end - start

    start = time()
    await cursor.execute(
        f"GET @{db_parameters['database']}.PUBLIC.teststage_python/{target_file_name} file://{data_dir}"
    )
    end = time()
    async_download_time = end - start

    unzip_file(os.path.join(data_dir, f"{target_file_name}.gz"))
    downloaded_content = read_csv(os.path.join(data_dir, target_file_name))

    # assert performance does not degrade too much
    assert async_upload_time <= max(sync_upload_time * 1.5, sync_upload_time + 5)
    assert async_download_time <= max(sync_download_time * 1.5, sync_download_time + 5)

    # assert file is not corrupted
    assert raw_content == downloaded_content


async def test_put_and_get_multiple_small_file(
    aio_connection, conn_cnx, db_parameters, tmpdir
):
    datadir = tmpdir.mkdir("test_put_and_get_multiple_small_file")
    data_dir = datadir.strpath
    target_file_name = "single_chunk_file"
    with conn_cnx() as cnx:
        start = time()
        cnx.cursor().execute(
            f"GET @{db_parameters['database']}.PUBLIC.teststage_python/{target_file_name} file://{data_dir}"
        )
        end = time()
        sync_download_time = end - start
        unzip_multiple_files(data_dir, target_file_name)

        start = time()
        cnx.cursor().execute(
            f"PUT file://{os.path.join(data_dir, target_file_name)}* @{db_parameters['database']}.PUBLIC.teststage_python OVERWRITE = TRUE"
        )
        end = time()
        sync_upload_time = end - start

    raw_content = read_multiple_csv(data_dir, target_file_name)

    await aio_connection.connect()
    cursor = aio_connection.cursor()
    start = time()
    await cursor.execute(
        f"PUT file://{os.path.join(data_dir, target_file_name)}* @{db_parameters['database']}.PUBLIC.teststage_python OVERWRITE = TRUE"
    )
    end = time()
    async_upload_time = end - start

    start = time()
    await cursor.execute(
        f"GET @{db_parameters['database']}.PUBLIC.teststage_python/{target_file_name} file://{data_dir}"
    )
    end = time()
    async_download_time = end - start

    unzip_multiple_files(data_dir, target_file_name)
    downloaded_content = read_multiple_csv(data_dir, target_file_name)

    # assert performance does not degrade too much
    assert async_upload_time <= max(sync_upload_time * 1.5, sync_upload_time + 5)
    assert async_download_time <= max(sync_download_time * 1.5, sync_download_time + 5)

    # assert file is not corrupted
    assert raw_content == downloaded_content
