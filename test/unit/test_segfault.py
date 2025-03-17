from base64 import b64decode
import os

from snowflake.connector.nanoarrow_arrow_iterator import PyArrowRowIterator
from snowflake.connector.arrow_context import ArrowConverterContext


THIS_DIR = os.path.dirname(os.path.realpath(__file__))


def test_parse():
    filepath = os.path.join(THIS_DIR, "../data", "segfault_payload.b64")
    with open(filepath) as f:
        data = b64decode(f.read().strip())

    it = PyArrowRowIterator(None, data, ArrowConverterContext(), False, False, False)
    row = next(it)

    print(row) # this prints rows without iterating them through Python, notice `<NULL>, <NULL>` - they are real, C-nulls! 
    row[0] # this segfaults the process