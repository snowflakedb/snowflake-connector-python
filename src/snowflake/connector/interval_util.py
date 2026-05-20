#!/usr/bin/env python


def interval_year_month_to_string(interval: int, scale: int) -> str:
    """Convert a year-month interval to a string.

    Args:
        interval: The year-month interval value in months.
        scale: The scale of the interval which represents subtype as follows:
            0: INTERVAL YEAR TO MONTH
            1: INTERVAL YEAR
            2: INTERVAL MONTH

    Returns:
        The string representation of the interval.
    """
    sign = "+" if interval >= 0 else "-"
    interval = abs(interval)
    if scale == 2:  # INTERVAL MONTH
        return f"{sign}{interval}"
    years = interval // 12
    if scale == 1:  # INTERVAL YEAR
        return f"{sign}{years}"
    # INTERVAL YEAR TO MONTH
    months = interval % 12
    return f"{sign}{years}-{months:02}"
