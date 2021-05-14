#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, Type


class MockUnknownError(Exception):
    """MockError a non-exist error to test how our code handled unexpected/unknown exception from utils"""

    pass


class MockRaise(object):
    """MockRaise is to customize ways to raise exceptions for testing.
    the same call on specific condition
    """

    MAX_FREQ = 1024 * 1024 * 1024

    @staticmethod
    def dummy_cond(params: Dict[str, Any]) -> bool:
        return True

    class RaiseErrConf:
        def __init__(
            self,
            raise_error: Exception,
            delay: int,
            cond_call: Callable[[Dict[str, Any]], bool],
        ):
            self.cond_call = cond_call
            self.delay = delay
            self.raise_error = raise_error

    def __init__(self, conf: RaiseErrConf, freq=1):
        self.call_count = 0
        self.calls = 0
        self.inject_conf = conf
        self.freq = freq  # freq = 1 is to trigger every time. freq = 1024 * 1024 * 1024, - always once

    def check_to_raise_error(self, func_name: str, **kwargs):
        self.call_count += 1
        if func_name not in self.inject_conf:
            return

        if (
            self.inject_conf.cond_call(kwargs)
            and (self.call_count - 1) % self.freq == 0
        ):
            if self.inject_conf.delay > 0:
                time.sleep(self.inject_conf.delay)
            raise self.inject_conf.raise_error


try:
    from azure.storage.blob import BlobClient, BlobType

    class MockBlobClient(BlobClient):
        def __init__(self, orig_cln=None):
            self.orig_cln = orig_cln
            self.calls = dict()
            self.errs = dict()

        #        self.check_raise_err = MockBlobClient.raise_once

        def check_raise_err(self, key: str):
            if key in self.calls:
                return
            self.calls[key] = 1
            for errkey in self.errs.keys():
                if key.find(errkey) >= 0:
                    raise self.errs[errkey]("mock err!")

        def set_raise_cfg(self, key: str, err_type: Type[Exception]):
            self.errs[key] = err_type

    def get_blob_properties(self, **kwargs):
        return BlobClient.get_blob_properties(self, **kwargs)

    def mock_upload_blob(  # pylint: disable=too-many-locals
        self,
        data,  # type: Union[Iterable[AnyStr], IO[AnyStr]]
        blob_type=BlobType.BlockBlob,  # type: Union[str, BlobType]
        length=None,  # type: Optional[int]
        metadata=None,  # type: Optional[Dict[str, str]]
        **kwargs
    ):
        BlobClient.mock_record.check_raise_err(data.name)
        return BlobClient.orig_upload_blob(
            self, data, blob_type, length, metadata, **kwargs
        )

    @contextmanager
    def patch_blob_client(
        key: str, err_type: Type[Exception]
    ) -> Generator["MockBlobClient", None, None]:
        BlobClient.mock_record = MockBlobClient()
        BlobClient.mock_record.set_raise_cfg(key, err_type)
        BlobClient.orig_upload_blob = BlobClient.upload_blob
        try:
            BlobClient.upload_blob = mock_upload_blob
            yield BlobClient.mock_record

        finally:
            BlobClient.upload_blob = BlobClient.orig_upload_blob


except ImportError:
    pass
