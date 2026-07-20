from __future__ import annotations

import logging

from snowflake.connector.secret_detector import SecretDetector


def add_filter_to_logger_and_children(
    base_logger_name: str, filter_instance: logging.Filter
) -> None:
    # Ensure the base logger exists and apply filter
    base_logger = logging.getLogger(base_logger_name)
    if filter_instance not in base_logger.filters:
        base_logger.addFilter(filter_instance)

    all_loggers_pairs = logging.root.manager.loggerDict.items()
    for name, obj in all_loggers_pairs:
        if not name.startswith(base_logger_name + "."):
            continue

        if not isinstance(obj, logging.Logger):
            continue  # Skip placeholders

        if filter_instance not in obj.filters:
            obj.addFilter(filter_instance)


class SecretMaskingFilter(logging.Filter):
    """
    A logging filter that masks sensitive information in log messages using the SecretDetector utility.

    This filter is designed for scenarios where you want to avoid applying SecretDetector globally
    as a formatter on all logging handlers. Global masking can introduce unnecessary computational
    overhead, particularly for internal logs where secrets are already handled explicitly.
    It would be also easy to bypass unintentionally by simply adding a neighbouring handler to a logger
    - without SecretDetector set as a formatter.

    On the other hand, libraries or submodules often do not have any handler attached, so formatting can't be
    configured on those level, while attaching new handler for that can cause unintended log output or its duplication.

    ⚠ Important:
        - Logging filters do **not** propagate down the logger hierarchy.
          To apply this filter across a hierarchy, use the `add_filter_to_logger_and_children` utility.
        - This filter causes **early formatting** of the log message (`record.getMessage()`),
          meaning `record.args` are merged into `record.msg` prematurely.
          If you rely on `record.args`, ensure this is the **last** filter in the chain.

    Notes:
        - The filter directly modifies `record.msg` with the masked version of the message.
        - It clears `record.args` to prevent re-formatting and ensure safe message output.

    Example:
        logger.addFilter(SecretMaskingFilter())
        handler.addFilter(SecretMaskingFilter())
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Format the message as it would be
            message = record.getMessage()

            # Run masking on the whole message
            masked_data = SecretDetector.mask_secrets(message)
            record.msg = masked_data.masked_text
        except Exception as ex:
            record.msg = SecretDetector.create_formatting_error_log(
                record, "EXCEPTION - " + str(ex)
            )
        finally:
            record.args = ()  # Avoid format re-application of formatting

        return True  # allow all logs through
