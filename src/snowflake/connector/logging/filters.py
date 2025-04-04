from __future__ import annotations

from logging import Filter, getLogger
from typing import Mapping

from ..secret_detector import SecretDetector

URLLIB3_MODULE_NAME = "snowflake.connector.vendored.urllib3.connectionpool"
# TODO: after migration to the external urllib3 from the vendored one, we should change filters here immediately to the below module's logger:
# URLLIB3_MODULE_NAME = "urllib3"


"""
Filter that will mask secrets in all messages of the logger it is assigned to.
It impacts performance significantly, thus should be used only when it is impossible to
apply masking secrets only to the appropriate messages' parts.

It is used for urllib3 vendored library, since we aim to migrate back to the external one.
"""


class AllSecretsFilter(Filter):
    @staticmethod
    def _mask_secrets_in_args_tuple(args: tuple) -> tuple:
        return tuple(
            map(lambda arg: SecretDetector.mask_secrets(arg).masked_text, args)
        )

    @staticmethod
    def _mask_secrets_in_msg(msg: str) -> str:
        return SecretDetector.mask_secrets(msg).masked_text

    @staticmethod
    def _mask_secrets_in_args_mapping(
        args: Mapping[str, object]
    ) -> Mapping[str, object]:
        return {
            key: SecretDetector.mask_secrets(value).masked_text
            for key, value in args.items()
        }

    @staticmethod
    def _mask_secrets_in_args(
        args: tuple[str] | Mapping[str, object]
    ) -> tuple[str] | Mapping[str, object]:
        if isinstance(args, tuple):
            return AllSecretsFilter._mask_secrets_in_args_tuple(args)
        else:
            return AllSecretsFilter._mask_secrets_in_args_mapping(args)

    def filter(self, record):
        record.msg = self._mask_secrets_in_msg(record.msg)
        record.args = self._mask_secrets_in_args(record.args)
        return True


def add_filters_to_loggers():
    getLogger(URLLIB3_MODULE_NAME).addFilter(AllSecretsFilter())


add_filters_to_loggers()
