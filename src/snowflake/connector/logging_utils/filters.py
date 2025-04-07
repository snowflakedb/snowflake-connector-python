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

    all_loggers_dict = logging.root.manager.loggerDict.items()
    child_loggers_gen = filter(
        lambda name_logger_pair: name_logger_pair[0].startswith(base_logger_name + "."),
        all_loggers_dict,
    )
    for _, obj in child_loggers_gen:
        if not isinstance(obj, logging.Logger):
            continue  # Skip placeholders

        if filter_instance not in obj.filters:
            obj.addFilter(filter_instance)


class SecretMaskingFilter(logging.Filter):
    """
    Another way to do it was using SecretDetector as Formatter for handlers of the external library.
    The problem occurs when no handlers are assigned - all logs are propagated to the top level handlers.
    We do not want to add SecretDetector as formatter to them (all logs) as it would incur unnecessary computational costs
    for the code we have full control over and can add this masking explicitly.

    Also we cannot just add handlers at the library level, as they may be incompatible with the settings user
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
