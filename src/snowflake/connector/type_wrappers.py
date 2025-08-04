from __future__ import annotations

from typing import Any

from snowflake.connector import converter


class snowflake_type_wrapper:
    pass


class snowflake_array(snowflake_type_wrapper, list):
    def __init__(self, seq=()):
        super().__init__(seq)
        self.original_type = type(seq)


class snowflake_object(snowflake_type_wrapper, dict):
    def __init__(self, seq=None, **kwargs):
        super().__init__(seq or {}, **kwargs)
        self.original_type = type(seq) if seq is not None else None


class snowflake_map(snowflake_type_wrapper, dict):
    def __init__(self, seq=None, **kwargs):
        super().__init__(seq or {}, **kwargs)
        self.original_type = type(seq) if seq is not None else None
        self.key_type = None
        self.key_attributes = {
            "nullable": True,
            "length": 0,
            "scale": 0,
            "precision": 36,
        }
        self.value_type = None
        self.value_attributes = {
            "nullable": True,
            "length": 0,
            "scale": 0,
            "precision": 36,
        }
        if seq:
            keys = list(self.keys())
            values = list(self.values())
            if keys:
                self.key_type = converter.infer_snowflake_type(keys[0])
                if not all(
                    converter.infer_snowflake_type(k) == self.key_type for k in keys
                ):
                    raise ValueError("All keys must have the same snowflake_type.")
            if values:
                self.value_type = converter.infer_snowflake_type(values[0])
                if not all(
                    converter.infer_snowflake_type(v) == self.value_type for v in values
                ):
                    raise ValueError("All values must have the same snowflake_type.")

        if self.key_type == "TIME":
            self.key_attributes = {
                "nullable": True,
                "length": 0,
                "scale": 9,
                "precision": 0,
            }

        if self.value_type == "TIME":
            self.value_attributes = {
                "nullable": True,
                "length": 0,
                "scale": 9,
                "precision": 0,
            }

    def __setitem__(self, key, value):
        key_type = converter.infer_snowflake_type(key)
        value_type = converter.infer_snowflake_type(value)
        if self.key_type is not None and key_type != self.key_type:
            raise ValueError("Key snowflake_type does not match existing key_type.")
        if self.value_type is not None and value_type != self.value_type:
            raise ValueError("Value snowflake_type does not match existing value_type.")
        if self.key_type is None:
            self.key_type = key_type
        if self.value_type is None:
            self.value_type = value_type
        super().__setitem__(key, value)


class snowflake_variant(snowflake_type_wrapper):
    def __init__(self, value: Any):
        raise NotImplementedError("snowflake_variant is currently unsupported.")
