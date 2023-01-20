#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector.query_context_cache import (
    QueryContextCache,
    QueryContextElement,
)


def test_serialization_deserialization():
    qce1 = QueryContextElement(id=1, read_timestamp=13323, priority=1, context=None)
    qce2 = QueryContextElement(
        id=2, read_timestamp=15522, priority=4, context=bytearray(b"")
    )
    qce3 = QueryContextElement(
        id=3, read_timestamp=8383, priority=99, context=bytearray(b"generic context")
    )
    qce_list = [qce1, qce2, qce3]

    qcc = QueryContextCache(5)
    for qce in qce_list:
        qcc.merge(qce.id, qce.read_timestamp, qce.priority, qce.context)

    data = qcc.serialize_to_arrow_base64()

    qcc.clear_cache()
    qcc.deserialize_from_arrow_base64(data)

    assert qcc.get_size() == 3
    assert qcc._last() == qce3
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce2
    qcc._remove_qce(qcc._last())
    assert qcc._last() == qce1
    qcc._remove_qce(qcc._last())

    assert qcc.get_size() == 0
