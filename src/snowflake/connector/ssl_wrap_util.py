#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

"""SSL wrap util for PyOpenSSL.

Copied from: https://github.com/shazow/urllib3/tree/master/urllib3/util to support ssl_wrap_socket.

Backport of selectors.py from Python 3.5+ to support Python < 3.4
Also has the behavior specified in PEP 475 which is to retry syscalls
in the case of an EINTR error. This module is required because selectors34
does not follow this behavior and instead returns that no dile descriptor
events have occurred rather than retry the syscall. The decision to drop
support for select.devpoll is made to maintain 100% test coverage.
"""


import select
import time
from selectors import EVENT_READ, EVENT_WRITE, DefaultSelector

try:
    monotonic = time.monotonic
except (AttributeError, ImportError):  # Python 3.3<
    monotonic = time.time

HAS_SELECT = True  # Variable that shows whether the platform has a selector.
_SYSCALL_SENTINEL = object()  # Sentinel in case a system call returns None.

if not hasattr(select, 'select'):  # Platform-specific: AppEngine
    HAS_SELECT = False


def _wait_for_io_events(socks, events, timeout=None):
    """Waits for IO events to be available from a list of sockets or optionally a single socket if passed in.

    Returns:
        A list of sockets that can be interacted with immediately.
    """
    if not HAS_SELECT:
        raise ValueError('Platform does not have a selector')
    if not isinstance(socks, list):
        # Probably just a single socket.
        if hasattr(socks, "fileno"):
            socks = [socks]
        # Otherwise it might be a non-list iterable.
        else:
            socks = list(socks)
    with DefaultSelector() as selector:
        for sock in socks:
            selector.register(sock, events)
        return [key[0].fileobj for key in
                selector.select(timeout) if key[1] & events]


def wait_for_read(socks, timeout=None):
    """Waits for reading to be available from a list of sockets or optionally a single socket if passed in.

    Returns:
        A list of sockets that can be read from immediately.
    """
    return _wait_for_io_events(socks, EVENT_READ, timeout)


def wait_for_write(socks, timeout=None):
    """Waits for writing to be available from a list of sockets`or optionally a single socket if passed in.

    Returns:
        A list of sockets that can be written to immediately.
    """
    return _wait_for_io_events(socks, EVENT_WRITE, timeout)
