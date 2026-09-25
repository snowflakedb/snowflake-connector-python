import hashlib
from io import BytesIO
from os import path

from snowflake.connector.file_util import SnowflakeFileUtil

THIS_DIR = path.dirname(path.realpath(__file__))
SAMPLE_FILE = path.join(THIS_DIR, "../data", "put_get_1.txt")


def test_get_md5_for_file():
    with open(SAMPLE_FILE, "rb") as f:
        md5_digest = SnowflakeFileUtil.get_md5(f)

    with open(SAMPLE_FILE, "rb") as f:
        contents = f.read()

    assert md5_digest == hashlib.md5(contents, usedforsecurity=False).digest()


def test_get_md5_for_stream_reseeks_to_zero():
    contents = b"some file contents for streaming md5 test"
    stream = BytesIO(contents)

    md5_digest = SnowflakeFileUtil.get_md5(stream)

    assert md5_digest == hashlib.md5(contents, usedforsecurity=False).digest()
    # get_md5 seeks back to 0 so the stream can still be read/uploaded afterward.
    assert stream.tell() == 0
