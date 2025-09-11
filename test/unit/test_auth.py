#!/usr/bin/env python
from __future__ import annotations

import copy
import inspect
import sys
import time
from typing import Optional, get_type_hints
from unittest.mock import Mock, PropertyMock

import pytest

import snowflake.connector.errors
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import SnowflakeRestful
from snowflake.connector.wif_util import (
    AttestationProvider,
    WorkloadIdentityAttestation,
)

from .mock_utils import mock_connection

try:  # pragma: no cover
    from snowflake.connector.auth import Auth, AuthByDefault, AuthByPlugin
except ImportError:
    from snowflake.connector.auth import Auth
    from snowflake.connector.auth_by_plugin import AuthByPlugin
    from snowflake.connector.auth_default import AuthByDefault


def _init_rest(application, post_requset):
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)
    connection._ocsp_mode = Mock(return_value=OCSPMode.FAIL_OPEN)
    type(connection).application = PropertyMock(return_value=application)
    type(connection)._internal_application_name = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._post_request = post_requset
    return rest


def _create_mock_auth_mfs_rest_response(next_action: str):
    def _mock_auth_mfa_rest_response(url, headers, body, **kwargs):
        """Tests successful case."""
        global mock_cnt
        _ = url
        _ = headers
        _ = body
        _ = kwargs.get("dummy")
        if mock_cnt == 0:
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "nextAction": next_action,
                    "inFlightCtx": "inFlightCtx",
                },
            }
        elif mock_cnt == 1:
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "TOKEN",
                    "masterToken": "MASTER_TOKEN",
                },
            }

        mock_cnt += 1
        return ret

    return _mock_auth_mfa_rest_response


def _mock_auth_mfa_rest_response_failure(url, headers, body, **kwargs):
    """Tests failed case."""
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get("dummy")

    if mock_cnt == 0:
        ret = {
            "success": True,
            "message": None,
            "data": {
                "nextAction": "EXT_AUTHN_DUO_ALL",
                "inFlightCtx": "inFlightCtx",
            },
        }
    elif mock_cnt == 1:
        ret = {
            "success": True,
            "message": None,
            "data": {
                "nextAction": "BAD",
                "inFlightCtx": "inFlightCtx",
            },
        }
    elif mock_cnt == 2:
        ret = {
            "success": True,
            "message": None,
            "data": None,
        }
    mock_cnt += 1
    return ret


def _mock_auth_mfa_rest_response_timeout(url, headers, body, **kwargs):
    """Tests timeout case."""
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get("dummy")
    if mock_cnt == 0:
        ret = {
            "success": True,
            "message": None,
            "data": {
                "nextAction": "EXT_AUTHN_DUO_ALL",
                "inFlightCtx": "inFlightCtx",
            },
        }
    elif mock_cnt == 1:
        time.sleep(10)  # should timeout while here
        ret = {}
    elif mock_cnt == 2:
        ret = {
            "success": True,
            "message": None,
            "data": None,
        }

    mock_cnt += 1
    return ret


def _get_most_derived_subclasses(cls):
    subclasses = cls.__subclasses__()
    if not subclasses:
        return [cls]
    most_derived = []
    for subclass in subclasses:
        most_derived.extend(_get_most_derived_subclasses(subclass))
    return most_derived


def _get_default_args_for_class(cls):
    def _get_default_arg_for_type(t, name):
        if getattr(t, "__origin__", None) is Optional:
            return None
        if t is str:
            if "url" in name or "uri" in name:
                return "https://example.com"
            return name
        if t is int:
            return 0
        if t is bool:
            return False
        if t is float:
            return 0.0
        if t is AttestationProvider:
            return AttestationProvider.GCP
        return None

    sig = inspect.signature(cls.__init__)
    type_hints = get_type_hints(
        cls.__init__, localns={"SnowflakeConnection": SnowflakeConnection}
    )

    args = {}
    for param in sig.parameters.values():
        if param.name != "self":
            param_type = type_hints.get(param.name, str)
            args[param.name] = _get_default_arg_for_type(param_type, param.name)
    return args


@pytest.mark.skipif(
    IS_WINDOWS,
    reason="There are consistent race condition issues with the global mock_cnt used for this test on windows",
)
@pytest.mark.parametrize(
    "next_action", ("EXT_AUTHN_DUO_ALL", "EXT_AUTHN_DUO_PUSH_N_PASSCODE")
)
def test_auth_mfa(next_action: str):
    """Authentication by MFA."""
    global mock_cnt
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    password = "testpassword"

    # success test case
    mock_cnt = 0
    rest = _init_rest(application, _create_mock_auth_mfs_rest_response(next_action))
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user)
    assert not rest._connection.errorhandler.called  # not error
    assert rest.token == "TOKEN"
    assert rest.master_token == "MASTER_TOKEN"

    # failure test case
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_mfa_rest_response_failure)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user)
    assert rest._connection.errorhandler.called  # error

    # timeout 1 second
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_mfa_rest_response_timeout)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user, timeout=1)
    assert rest._connection.errorhandler.called  # error

    # ret["data"] is none
    with pytest.raises(snowflake.connector.errors.Error):
        mock_cnt = 2
        rest = _init_rest(application, _mock_auth_mfa_rest_response_timeout)
        auth = Auth(rest)
        auth_instance = AuthByDefault(password)
        auth.authenticate(auth_instance, account, user)


def _mock_auth_password_change_rest_response(url, headers, body, **kwargs):
    """Test successful case."""
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get("dummy")
    if mock_cnt == 0:
        ret = {
            "success": True,
            "message": None,
            "data": {
                "nextAction": "PWD_CHANGE",
                "inFlightCtx": "inFlightCtx",
            },
        }
    elif mock_cnt == 1:
        ret = {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    mock_cnt += 1
    return ret


def test_auth_password_change():
    """Tests password change."""
    global mock_cnt

    def _password_callback():
        return "NEW_PASSWORD"

    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    password = "testpassword"

    # success test case
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_password_change_rest_response)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(
        auth_instance, account, user, password_callback=_password_callback
    )
    assert not rest._connection.errorhandler.called  # not error


def test_authbyplugin_abc_api():
    """This test verifies that the abstract function signatures have not changed."""
    bc = AuthByPlugin

    # Verify properties
    assert inspect.isdatadescriptor(bc.timeout)
    assert inspect.isdatadescriptor(bc.type_)
    assert inspect.isdatadescriptor(bc.assertion_content)

    # Verify method signatures
    # update_body
    if sys.version_info < (3, 12):
        assert inspect.isfunction(bc.update_body)
        assert str(inspect.signature(bc.update_body).parameters) == (
            "OrderedDict([('self', <Parameter \"self\">), "
            "('body', <Parameter \"body: 'dict[Any, Any]'\">)])"
        )

        # authenticate
        assert inspect.isfunction(bc.prepare)
        assert str(inspect.signature(bc.prepare).parameters) == (
            "OrderedDict([('self', <Parameter \"self\">), "
            "('conn', <Parameter \"conn: 'SnowflakeConnection'\">), "
            "('authenticator', <Parameter \"authenticator: 'str'\">), "
            "('service_name', <Parameter \"service_name: 'str | None'\">), "
            "('account', <Parameter \"account: 'str'\">), "
            "('user', <Parameter \"user: 'str'\">), "
            "('password', <Parameter \"password: 'str | None'\">), "
            "('kwargs', <Parameter \"**kwargs: 'Any'\">)])"
        )

        # handle_failure
        assert inspect.isfunction(bc._handle_failure)
        assert str(inspect.signature(bc._handle_failure).parameters) == (
            "OrderedDict([('self', <Parameter \"self\">), "
            "('conn', <Parameter \"conn: 'SnowflakeConnection'\">), "
            "('ret', <Parameter \"ret: 'dict[Any, Any]'\">), "
            "('kwargs', <Parameter \"**kwargs: 'Any'\">)])"
        )

        # handle_timeout
        assert inspect.isfunction(bc.handle_timeout)
        assert str(inspect.signature(bc.handle_timeout).parameters) == (
            "OrderedDict([('self', <Parameter \"self\">), "
            "('authenticator', <Parameter \"authenticator: 'str'\">), "
            "('service_name', <Parameter \"service_name: 'str | None'\">), "
            "('account', <Parameter \"account: 'str'\">), "
            "('user', <Parameter \"user: 'str'\">), "
            "('password', <Parameter \"password: 'str'\">), "
            "('kwargs', <Parameter \"**kwargs: 'Any'\">)])"
        )
    else:
        # starting from python 3.12 the repr of collections.OrderedDict is changed
        # to use regular dictionary formating instead of pairs of keys and values.
        # see https://github.com/python/cpython/issues/101446
        assert inspect.isfunction(bc.update_body)
        assert str(inspect.signature(bc.update_body).parameters) == (
            """OrderedDict({'self': <Parameter "self">, \
'body': <Parameter "body: 'dict[Any, Any]'">})"""
        )

        # authenticate
        assert inspect.isfunction(bc.prepare)
        assert str(inspect.signature(bc.prepare).parameters) == (
            """OrderedDict({'self': <Parameter "self">, \
'conn': <Parameter "conn: 'SnowflakeConnection'">, \
'authenticator': <Parameter "authenticator: 'str'">, \
'service_name': <Parameter "service_name: 'str | None'">, \
'account': <Parameter "account: 'str'">, \
'user': <Parameter "user: 'str'">, \
'password': <Parameter "password: 'str | None'">, \
'kwargs': <Parameter "**kwargs: 'Any'">})"""
        )

        # handle_failure
        assert inspect.isfunction(bc._handle_failure)
        assert str(inspect.signature(bc._handle_failure).parameters) == (
            """OrderedDict({'self': <Parameter "self">, \
'conn': <Parameter "conn: 'SnowflakeConnection'">, \
'ret': <Parameter "ret: 'dict[Any, Any]'">, \
'kwargs': <Parameter "**kwargs: 'Any'">})"""
        )

        # handle_timeout
        assert inspect.isfunction(bc.handle_timeout)
        assert str(inspect.signature(bc.handle_timeout).parameters) == (
            """OrderedDict({'self': <Parameter "self">, \
'authenticator': <Parameter "authenticator: 'str'">, \
'service_name': <Parameter "service_name: 'str | None'">, \
'account': <Parameter "account: 'str'">, \
'user': <Parameter "user: 'str'">, \
'password': <Parameter "password: 'str'">, \
'kwargs': <Parameter "**kwargs: 'Any'">})"""
        )


@pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="Typing using '|' requires python 3.10 or higher (PEP 604)",
)
@pytest.mark.parametrize("auth_method", _get_most_derived_subclasses(AuthByPlugin))
def test_auth_prepare_body_does_not_overwrite_fields(auth_method):
    ocsp_mode = Mock()
    ocsp_mode.name = "ocsp_mode"
    session_manager = Mock()
    session_manager.clone = lambda max_retries: "session_manager"

    req_body_before = Auth.base_auth_data(
        "user",
        "account",
        "application",
        "internal_application_name",
        "internal_application_version",
        ocsp_mode,
        login_timeout=60 * 60,
        network_timeout=60 * 60,
        socket_timeout=60 * 60,
        platform_detection_timeout_seconds=0.2,
        session_manager=session_manager,
    )
    req_body_after = copy.deepcopy(req_body_before)
    additional_args = _get_default_args_for_class(auth_method)
    auth_class = auth_method(**additional_args)
    auth_class.attestation = WorkloadIdentityAttestation(
        provider=AttestationProvider.GCP,
        credential=None,
        user_identifier_components=None,
    )
    auth_class.update_body(req_body_after)

    # Check that the values in the body before are a strict subset of the values in the body after.
    # Must use all() for this comparison because lists are not hashable
    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )
    req_body_before["data"].pop("CLIENT_ENVIRONMENT")
    req_body_after["data"].pop("CLIENT_ENVIRONMENT")
    assert set(req_body_before["data"].items()) <= set(req_body_after["data"].items())
