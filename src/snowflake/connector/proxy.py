#!/usr/bin/env python
from __future__ import annotations


def get_proxy_url(
    proxy_host: str | None,
    proxy_port: str | None,
    proxy_user: str | None = None,
    proxy_password: str | None = None,
) -> str | None:
    http_prefix = "http://"
    https_prefix = "https://"

    if not proxy_host or not proxy_port:
        return None
    if proxy_host.startswith(http_prefix):
        host = proxy_host[len(http_prefix) :]
    elif proxy_host.startswith(https_prefix):
        host = proxy_host[len(https_prefix) :]
    else:
        host = proxy_host
    auth = (
        f"{proxy_user or ''}:{proxy_password or ''}@"
        if proxy_user or proxy_password
        else ""
    )
    return f"{http_prefix}{auth}{host}:{proxy_port}"
