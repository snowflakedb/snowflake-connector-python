import logging


def initialize_logger(name=__name__, level=logging.INFO):
    """
    Initializes and configures a logger.

    Args:
        name (str): The name of the logger.
        level (int): The logging level (e.g., logging.INFO, logging.DEBUG).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create a console handler
    handler = logging.StreamHandler()
    handler.setLevel(level)

    # Create a formatter and set it for the handler
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)

    # Add the handler to the logger
    if not logger.handlers:  # Avoid duplicate handlers
        logger.addHandler(handler)

    return logger
