#!/usr/bin/env python


def interval_year_month_to_string(interval: int) -> str:
    """Convert a year-month interval to a string.

    Args:
        interval: The year-month interval.

    Returns:
        The string representation of the interval.
    """
    sign = "+" if interval >= 0 else "-"
    interval = abs(interval)
    years = interval // 12
    months = interval % 12
    return f"{sign}{years}-{months:02}"
