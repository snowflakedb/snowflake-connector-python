from typing import Protocol, runtime_checkable


@runtime_checkable
class BrowserProtocol(Protocol):
    def open_new(str) -> None:
        ...
