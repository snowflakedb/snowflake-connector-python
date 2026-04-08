from __future__ import annotations

import re
import uuid
from unittest.mock import MagicMock

import pytest

from snowflake.connector import errors


def test_detecting_duplicate_detail_insertion():
    sfqid = str(uuid.uuid4())
    query = "select something_really_buggy from buggy_table"
    sqlstate = "24000"
    errno = 123456
    msg = "Some error happened"
    expected_msg = re.compile(rf"{errno} \({sqlstate}\): {sfqid}: {msg}")
    original_ex = errors.ProgrammingError(
        sqlstate=sqlstate,
        sfqid=sfqid,
        query=query,
        errno=errno,
        msg=msg,
    )
    # Test whether regular exception confirms to what we expect to see
    assert expected_msg.fullmatch(original_ex.msg)

    # Test whether exception with flag confirms to what we expect to see
    assert errors.ProgrammingError(
        msg=original_ex.msg,
        done_format_msg=True,
    )
    # Test whether exception with auto detection confirms to what we expect to see
    assert errors.ProgrammingError(
        msg=original_ex.msg,
    )


def test_args():
    assert errors.Error("msg").args == ("msg",)

def test_default_errorhandler_raises_programming_error():
    with pytest.raises(errors.ProgrammingError) as exc_info:
        errors.Error.default_errorhandler(
            None,
            None,
            errors.ProgrammingError,
            {
                "msg": "Some error happened",
                "errno": 123456,
                "sqlstate": "24000",
            },
        )

    assert exc_info.value.errno == 123456
    assert exc_info.value.sqlstate == "24000"
    assert "Some error happened" in exc_info.value.msg


def test_errorhandler_wrapper_passes_structured_payload_to_custom_handler():
    captured = {}

    def handler(connection, cursor, error_class, error_value):
        captured["connection"] = connection
        captured["cursor"] = cursor
        captured["error_class"] = error_class
        captured["error_value"] = error_value

    connection = MagicMock()
    connection.messages = []

    cursor = MagicMock()
    cursor.messages = []
    cursor.errorhandler = handler

    errors.Error.errorhandler_wrapper(
        connection,
        cursor,
        errors.ProgrammingError,
        {
            "msg": "Boom",
            "errno": 123,
        },
    )

    assert captured["connection"] is connection
    assert captured["cursor"] is cursor
    assert captured["error_class"] is errors.ProgrammingError
    assert captured["error_value"]["msg"] == "Boom"
    assert captured["error_value"]["errno"] == 123
    assert captured["error_value"]["done_format_msg"] is False
    assert connection.messages[0][0] is errors.ProgrammingError
    assert cursor.messages[0][0] is errors.ProgrammingError

def test_errorhandler_wrapper_from_ready_exception_normalizes_error_instances():
    captured = {}

    def handler(connection, cursor, error_class, error_value):
        captured["error_class"] = error_class
        captured["error_value"] = error_value

    connection = MagicMock()
    connection.messages = []

    cursor = MagicMock()
    cursor.messages = []
    cursor.errorhandler = handler

    error_exc = errors.ProgrammingError(
        msg="Boom",
        errno=123,
        sqlstate="24000",
    )

    errors.Error.errorhandler_wrapper_from_ready_exception(
        connection,
        cursor,
        error_exc,
    )

    assert captured["error_class"] is errors.ProgrammingError
    assert captured["error_value"]["msg"] == error_exc.msg
    assert captured["error_value"]["errno"] == error_exc.errno
    assert captured["error_value"]["sqlstate"] == error_exc.sqlstate
    assert captured["error_value"]["done_format_msg"] is True

def test_errorhandler_wrapper_from_ready_exception_reraises_generic_exception():
    with pytest.raises(Exception, match="boom"):
        errors.Error.errorhandler_wrapper_from_ready_exception(
            None,
            None,
            Exception("boom"),
        )
