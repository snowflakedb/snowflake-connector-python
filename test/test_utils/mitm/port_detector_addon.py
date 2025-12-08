"""mitmproxy addon to detect the dynamically assigned port.

This addon is loaded by mitmdump when using --listen-port 0 (auto-assign).
When mitmproxy finishes starting, the `running()` hook writes the assigned
port to a temporary file that the test fixture reads.

Reference: https://github.com/mitmproxy/mitmproxy/discussions/6011
"""

import logging
import os
import sys

from mitmproxy import ctx

logger = logging.getLogger(__name__)


def running():
    """Called when mitmproxy is fully started and ready.

    Retrieves the actual port that was bound (when using --listen-port 0)
    and writes it to a file specified via MITM_PORT_FILE environment variable.
    """
    port_file = os.environ.get("MITM_PORT_FILE")
    if not port_file:
        logger.error("MITM_PORT_FILE environment variable not set!")
        sys.exit(1)

    # Get the actual port that was bound
    # ctx.master.addons.get("proxyserver").listen_addrs() returns:
    # [('::', port, 0, 0), ('0.0.0.0', port)]
    addrs = ctx.master.addons.get("proxyserver").listen_addrs()
    if not addrs:
        logger.error("No proxy server addresses found!")
        sys.exit(1)

    port = addrs[0][1]

    try:
        with open(port_file, "w") as f:
            f.write(str(port))
        logger.info("Proxy listening on port %s, written to %s", port, port_file)
    except OSError as e:
        logger.error("Failed to write port to %s: %s", port_file, e)
        sys.exit(1)
