#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from typing import Pattern, Sequence, Tuple, Union


def verify_log_tuple(
    module: str,
    level: int,
    message: Union[str, Pattern],
    log_tuples: Sequence[Tuple[str, int, str]],
):
    """Convenience function to be able to search for regex patterns in log messages.

    Designed to search caplog.record_tuples.

    Notes:
        - module could be extended to take a pattern too
    """
    for _module, _level, _message in log_tuples:
        if _module == module and _level == level:
            if _message == message or (
                isinstance(message, Pattern) and message.search(_message)
            ):
                return True
    return False
