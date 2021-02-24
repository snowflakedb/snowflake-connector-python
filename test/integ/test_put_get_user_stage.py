#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import mimetypes
import os
import time
from getpass import getuser
from logging import getLogger

import pytest

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import put


@pytest.mark.aws
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_get_small_data_via_user_stage(
    is_public_test, tmpdir, conn_cnx, db_parameters, from_path
):
    """[s3] Puts and Gets Small Data via User Stage."""
    if is_public_test or "AWS_ACCESS_KEY_ID" not in os.environ:
        pytest.skip("This test requires to change the internal parameter")
    number_of_files = 5 if from_path else 1
    number_of_lines = 1
    _put_get_user_stage(
        tmpdir,
        conn_cnx,
        db_parameters,
        number_of_files=number_of_files,
        number_of_lines=number_of_lines,
        from_path=from_path,
    )


@pytest.mark.aws
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_get_large_data_via_user_stage(
    is_public_test, tmpdir, conn_cnx, db_parameters, from_path
):
    """[s3] Puts and Gets Large Data via User Stage."""
    if is_public_test or "AWS_ACCESS_KEY_ID" not in os.environ:
        pytest.skip("This test requires to change the internal parameter")
    number_of_files = 2 if from_path else 1
    number_of_lines = 200000
    _put_get_user_stage(
        tmpdir,
        conn_cnx,
        db_parameters,
        number_of_files=number_of_files,
        number_of_lines=number_of_lines,
        from_path=from_path,
    )


def _put_get_user_stage(
    tmpdir,
    conn_cnx,
    db_parameters,
    number_of_files=1,
    number_of_lines=1,
    from_path=True,
):
    # sanity check
    assert "AWS_ACCESS_KEY_ID" in os.environ, "AWS_ACCESS_KEY_ID is missing"
    assert "AWS_SECRET_ACCESS_KEY" in os.environ, "AWS_SECRET_ACCESS_KEY is missing"
    if not from_path:
        assert number_of_files == 1

    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    files = os.path.join(tmp_dir, "file*" if from_path else os.listdir(tmp_dir)[0])
    file_stream = None if from_path else open(files, "rb")

    stage_name = db_parameters["name"] + "_stage_{}_{}".format(
        number_of_files, number_of_lines
    )
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""".format(
                name=db_parameters["name"]
            )
        )
        user_bucket = os.getenv(
            "SF_AWS_USER_BUCKET", "sfc-dev1-regression/{}/reg".format(getuser())
        )
        cnx.cursor().execute(
            """
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}-{number_of_files}-{number_of_lines}'
credentials=(
 AWS_KEY_ID='{aws_key_id}'
 AWS_SECRET_KEY='{aws_secret_key}'
)
""".format(
                stage_name=stage_name,
                user_bucket=user_bucket,
                aws_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                number_of_files=number_of_files,
                number_of_lines=number_of_lines,
            )
        )
    try:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                "alter session set disable_put_and_get_on_external_stage = false"
            )
            cnx.cursor().execute("rm @{stage_name}".format(stage_name=stage_name))

            put(cnx.cursor(), files, stage_name, from_path, file_stream=file_stream)
            cnx.cursor().execute(
                "copy into {name} from @{stage_name}".format(
                    name=db_parameters["name"], stage_name=stage_name
                )
            )
            c = cnx.cursor()
            try:
                c.execute(
                    "select count(*) from {name}".format(name=db_parameters["name"])
                )
                rows = 0
                for rec in c:
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                c.close()
            cnx.cursor().execute("rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "copy into @{stage_name} from {name}".format(
                    name=db_parameters["name"], stage_name=stage_name
                )
            )
            tmp_dir_user = str(tmpdir.mkdir("put_get_stage"))
            cnx.cursor().execute(
                "get @{stage_name}/ file://{tmp_dir_user}/".format(
                    stage_name=stage_name, tmp_dir_user=tmp_dir_user
                )
            )
            for _, _, files in os.walk(tmp_dir_user):
                for file in files:
                    mimetypes.init()
                    _, encoding = mimetypes.guess_type(file)
                    assert encoding == "gzip", "exported file type"
    finally:
        if file_stream:
            file_stream.close()
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute("rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(stage_name=stage_name)
            )
            cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )


@pytest.mark.aws
@pytest.mark.flaky(reruns=3)
def test_put_get_duplicated_data_user_stage(
    is_public_test,
    tmpdir,
    conn_cnx,
    db_parameters,
    number_of_files=5,
    number_of_lines=100,
):
    """[s3] Puts and Gets Duplicated Data using User Stage."""
    if is_public_test or "AWS_ACCESS_KEY_ID" not in os.environ:
        pytest.skip("This test requires to change the internal parameter")

    logger = getLogger(__name__)
    assert "AWS_ACCESS_KEY_ID" in os.environ, "AWS_ACCESS_KEY_ID is missing"
    assert "AWS_SECRET_ACCESS_KEY" in os.environ, "AWS_SECRET_ACCESS_KEY is missing"

    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")

    stage_name = db_parameters["name"] + "_stage"
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""".format(
                name=db_parameters["name"]
            )
        )
        user_bucket = os.getenv(
            "SF_AWS_USER_BUCKET", "sfc-dev1-regression/{}/reg".format(getuser())
        )
        cnx.cursor().execute(
            """
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}-{number_of_files}-{number_of_lines}'
credentials=(
 AWS_KEY_ID='{aws_key_id}'
 AWS_SECRET_KEY='{aws_secret_key}'
)
""".format(
                stage_name=stage_name,
                user_bucket=user_bucket,
                aws_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                number_of_files=number_of_files,
                number_of_lines=number_of_lines,
            )
        )
    try:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            c = cnx.cursor()
            try:
                for rec in c.execute("rm @{stage_name}".format(stage_name=stage_name)):
                    logger.info("rec=%s", rec)
            finally:
                c.close()

            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            c.execute("alter session set disable_put_and_get_on_external_stage = false")
            try:
                for rec in c.execute(
                    "put file://{file} @{stage_name}".format(
                        file=files, stage_name=stage_name
                    )
                ):
                    logger.info("rec=%s", rec)
                    if rec[6] == "UPLOADED":
                        success_cnt += 1
                    elif rec[6] == "SKIPPED":
                        skipped_cnt += 1
            finally:
                c.close()
            assert success_cnt == number_of_files, "uploaded files"
            assert skipped_cnt == 0, "skipped files"

            logger.info("deleting files in {stage_name}".format(stage_name=stage_name))

            deleted_cnt = 0
            cnx.cursor().execute("rm @{stage_name}/file0".format(stage_name=stage_name))
            deleted_cnt += 1
            cnx.cursor().execute("rm @{stage_name}/file1".format(stage_name=stage_name))
            deleted_cnt += 1
            cnx.cursor().execute("rm @{stage_name}/file2".format(stage_name=stage_name))
            deleted_cnt += 1

            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            try:
                for rec in c.execute(
                    "put file://{file} @{stage_name}".format(
                        file=files, stage_name=stage_name
                    ),
                    _raise_put_get_error=False,
                ):
                    logger.info("rec=%s", rec)
                    if rec[6] == "UPLOADED":
                        success_cnt += 1
                    elif rec[6] == "SKIPPED":
                        skipped_cnt += 1
                assert success_cnt == deleted_cnt, "uploaded files in the second time"
                assert (
                    skipped_cnt == number_of_files - deleted_cnt
                ), "skipped files in the second time"
            finally:
                c.close()

            time.sleep(5)
            cnx.cursor().execute(
                "copy into {name} from @{stage_name}".format(
                    name=db_parameters["name"], stage_name=stage_name
                )
            )
            c = cnx.cursor()
            try:
                c.execute(
                    "select count(*) from {name}".format(name=db_parameters["name"])
                )
                rows = 0
                for rec in c:
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                c.close()
            cnx.cursor().execute("rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "copy into @{stage_name} from {name}".format(
                    name=db_parameters["name"], stage_name=stage_name
                )
            )
            tmp_dir_user = str(tmpdir.mkdir("stage2"))
            cnx.cursor().execute(
                "get @{stage_name}/ file://{tmp_dir_user}/".format(
                    stage_name=stage_name, tmp_dir_user=tmp_dir_user
                )
            )
            for _, _, files in os.walk(tmp_dir_user):
                for file in files:
                    mimetypes.init()
                    _, encoding = mimetypes.guess_type(file)
                    assert encoding == "gzip", "exported file type"

    finally:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(stage_name=stage_name)
            )
            cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )


@pytest.mark.aws
def test_get_data_user_stage(is_public_test, tmpdir, conn_cnx, db_parameters):
    """SNOW-20927: Tests Get failure with 404 error."""
    if is_public_test or "AWS_ACCESS_KEY_ID" not in os.environ:
        pytest.skip("This test requires to change the internal parameter")

    default_s3bucket = os.getenv(
        "SF_AWS_USER_BUCKET", "sfc-dev1-regression/{}/reg".format(getuser())
    )
    test_data = [
        {
            "s3location": "{}/{}".format(
                default_s3bucket, db_parameters["name"] + "_stage"
            ),
            "stage_name": db_parameters["name"] + "_stage1",
            "data_file_name": "data.txt",
        },
    ]
    for elem in test_data:
        _put_list_rm_files_in_stage(tmpdir, conn_cnx, db_parameters, elem)


def _put_list_rm_files_in_stage(tmpdir, conn_cnx, db_parameters, elem):
    s3location = elem["s3location"]
    stage_name = elem["stage_name"]
    data_file_name = elem["data_file_name"]

    from io import open

    from snowflake.connector.compat import UTF8

    tmp_dir = str(tmpdir.mkdir("data"))
    data_file = os.path.join(tmp_dir, data_file_name)
    with open(data_file, "w", encoding=UTF8) as f:
        f.write(str("123,456,string1\n"))
        f.write(str("789,012,string2\n"))

    output_dir = str(tmpdir.mkdir("output"))
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
create or replace stage {stage_name}
    url='s3://{s3location}'
    credentials=(
        AWS_KEY_ID='{aws_key_id}'
        AWS_SECRET_KEY='{aws_secret_key}'
    )
""".format(
                s3location=s3location,
                stage_name=stage_name,
                aws_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            )
        )
    try:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                """
RM @{stage_name}
""".format(
                    stage_name=stage_name
                )
            )
            cnx.cursor().execute(
                "alter session set disable_put_and_get_on_external_stage = false"
            )
            rec = (
                cnx.cursor()
                .execute(
                    """
PUT file://{file} @{stage_name}
""".format(
                        file=data_file, stage_name=stage_name
                    )
                )
                .fetchone()
            )
            assert rec[0] == data_file_name
            assert rec[6] == "UPLOADED"
            rec = (
                cnx.cursor()
                .execute(
                    """
LIST @{stage_name}
            """.format(
                        stage_name=stage_name
                    )
                )
                .fetchone()
            )
            assert rec, "LIST should return something"
            assert rec[0].startswith("s3://"), "The file location in S3"
            rec = (
                cnx.cursor()
                .execute(
                    """
GET @{stage_name} file://{output_dir}
""".format(
                        stage_name=stage_name, output_dir=output_dir
                    )
                )
                .fetchone()
            )
            assert rec[0] == data_file_name + ".gz"
            assert rec[2] == "DOWNLOADED"
    finally:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                """
RM @{stage_name}
""".format(
                    stage_name=stage_name
                )
            )
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(stage_name=stage_name)
            )
