from __future__ import annotations

import logging

from snowflake.connector.secret_detector import SecretDetector


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
