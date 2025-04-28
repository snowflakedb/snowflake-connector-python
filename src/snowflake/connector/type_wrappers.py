from __future__ import annotations

from typing import Any


class snowflake_type_wrapper:
    pass


class snowflake_array(snowflake_type_wrapper, list):
    def __init__(self, seq=(), desired_snowflake_type: str | None = None):
        super().__init__(seq)
        self.original_type = type(seq)
        self.desired_snowflake_type = desired_snowflake_type


class snowflake_object(snowflake_type_wrapper, dict):
    def __init__(self, seq=None, **kwargs):
        super().__init__(seq or {}, **kwargs)
        self.original_type = type(seq) if seq is not None else None


class snowflake_map(snowflake_type_wrapper, dict):
    def __init__(self, seq=None, **kwargs):
        super().__init__(seq or {}, **kwargs)
        self.original_type = type(seq) if seq is not None else None


class snowflake_variant(snowflake_type_wrapper):
    def __init__(self, value: Any):
        self.value = value
