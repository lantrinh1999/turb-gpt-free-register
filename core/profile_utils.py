# -*- coding: utf-8 -*-
"""Registration profile generation utilities."""

from __future__ import annotations

import random
from datetime import date, timedelta


def _shift_year_safe(day: date, years: int) -> date:
    """Shift a date by years; when the date is Feb 29 and the target year is not a leap year, fall back to Feb 28."""
    try:
        return day.replace(year=day.year + years)
    except ValueError:
        return day.replace(year=day.year + years, month=2, day=28)


def generate_random_birthday(min_age: int = 18, max_age: int = 65) -> str:
    """
    Generate a random birthday whose age is within the closed interval [min_age, max_age], in the format YYYY-MM-DD.

    For example, by default a random day is picked between the day one turns 65 and the day one turns 18.
    """
    if min_age < 0 or max_age < min_age:
        raise ValueError(f"Invalid age range: min_age={min_age}, max_age={max_age}")

    today = date.today()
    oldest = _shift_year_safe(today, -max_age)
    youngest = _shift_year_safe(today, -min_age)
    span_days = (youngest - oldest).days
    birthday = oldest + timedelta(days=random.randint(0, span_days))
    return birthday.isoformat()
