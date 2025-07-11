#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import socket
import time
from threading import Thread

import pytest

from snowflake.connector.auth._http_server import AuthHttpServer
from snowflake.connector.vendored import requests


@pytest.mark.parametrize(
    "dontwait",
    ["false", "true"],
)
@pytest.mark.parametrize("timeout", [None, 0.05])
@pytest.mark.parametrize("reuse_port", ["true"])
def test_auth_callback_success(monkeypatch, dontwait, timeout, reuse_port) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", reuse_port)
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", dontwait)
    test_response: requests.Response | None = None
    with AuthHttpServer(
        uri="http://127.0.0.1/test_request",
        redirect_uri="http://127.0.0.1/test_request",
    ) as callback_server:

        def request_callback():
            nonlocal test_response
            if timeout:
                time.sleep(timeout / 5)
            test_response = requests.get(
                f"http://{callback_server.hostname}:{callback_server.port}/test_request"
            )

        request_callback_thread = Thread(target=request_callback)
        request_callback_thread.start()
        block, client_socket = callback_server.receive_block(timeout=timeout)
        test_callback_request = block[0]
        response = ["HTTP/1.1 200 OK", "Content-Type: text/html", "", "test_response"]
        client_socket.sendall("\r\n".join(response).encode("utf-8"))
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
        request_callback_thread.join()
        assert test_response.ok
        assert test_response.text == "test_response"
        assert test_callback_request == "GET /test_request HTTP/1.1"


@pytest.mark.parametrize(
    "dontwait",
    ["false", "true"],
)
@pytest.mark.parametrize("timeout", [0.05])
@pytest.mark.parametrize("reuse_port", ["true"])
def test_auth_callback_timeout(monkeypatch, dontwait, timeout, reuse_port) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", reuse_port)
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", dontwait)
    with AuthHttpServer(
        uri="http://127.0.0.1/test_request",
        redirect_uri="http://127.0.0.1/test_request",
    ) as callback_server:
        block, client_socket = callback_server.receive_block(timeout=timeout)
        assert block is None
        assert client_socket is None


@pytest.mark.parametrize(
    "socket_host",
    [
        "127.0.0.1",
        "localhost",
    ],
)
@pytest.mark.parametrize(
    "socket_port",
    [
        "",
        ":0",
        ":12345",
    ],
)
@pytest.mark.parametrize(
    "redirect_host",
    [
        "127.0.0.1",
        "localhost",
    ],
)
@pytest.mark.parametrize(
    "redirect_port",
    [
        "",
        ":0",
        ":12345",
    ],
)
@pytest.mark.parametrize(
    "dontwait",
    ["false", "true"],
)
@pytest.mark.parametrize("reuse_port", ["true", "false"])
def test_auth_callback_server_updates_localhost_redirect_uri_port_to_match_socket_port(
    monkeypatch,
    socket_host,
    socket_port,
    redirect_host,
    redirect_port,
    dontwait,
    reuse_port,
) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", reuse_port)
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", dontwait)
    with AuthHttpServer(
        uri=f"http://{socket_host}{socket_port}/test_request",
        redirect_uri=f"http://{redirect_host}{redirect_port}/test_request",
    ) as callback_server:
        assert callback_server._redirect_uri.port == callback_server.port


@pytest.mark.parametrize(
    "socket_host",
    [
        "127.0.0.1",
        "localhost",
    ],
)
@pytest.mark.parametrize(
    "socket_port",
    [
        "",
        ":0",
        ":12345",
    ],
)
@pytest.mark.parametrize(
    "redirect_port",
    [
        "",
        ":0",
        ":12345",
    ],
)
@pytest.mark.parametrize(
    "dontwait",
    ["false", "true"],
)
@pytest.mark.parametrize("reuse_port", ["true", "false"])
def test_auth_callback_server_does_not_updates_nonlocalhost_redirect_uri_port_to_match_socket_port(
    monkeypatch, socket_host, socket_port, redirect_port, dontwait, reuse_port
) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", reuse_port)
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", dontwait)
    redirect_uri = f"http://not_localhost{redirect_port}/test_request"
    with AuthHttpServer(
        uri=f"http://{socket_host}{socket_port}/test_request", redirect_uri=redirect_uri
    ) as callback_server:
        assert callback_server.redirect_uri == redirect_uri
