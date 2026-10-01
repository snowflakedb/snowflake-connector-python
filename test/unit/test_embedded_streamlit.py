#!/usr/bin/env python
from __future__ import annotations

from unittest import mock
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest

from snowflake.connector.embedded_streamlit import (
    SUBJECT_TOKEN_TYPE_JWT,
    SUBJECT_TOKEN_TYPE_PAT,
    SUBJECT_TOKEN_TYPE_SESSION,
    EmbeddedStreamlit,
)
from snowflake.connector.errors import ProgrammingError

STREAMLIT_ID = "MYDB.MYSCHEMA.MY_APP"
PARENT_ORIGIN = "https://analytics.example.com"
ENDPOINT = "https://fake.example.com/oauth/token"


class _FakeResponse:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code=200, payload=None, raise_on_json=False):
        self.status_code = status_code
        self._payload = payload
        self._raise_on_json = raise_on_json

    def json(self):
        if self._raise_on_json:
            raise ValueError("not json")
        return self._payload


def _fake_manager(response):
    """Return a mock SessionManager whose .post() returns *response*."""
    manager = mock.MagicMock()
    manager.post.return_value = response
    return manager


def _ok_manager(redirect_uri, expires_in=3600):
    return _fake_manager(
        _FakeResponse(
            status_code=200,
            payload={"redirect_uri": redirect_uri, "expires_in": expires_in},
        )
    )


def _posted_body(manager):
    """Parse the form-urlencoded body sent to manager.post() into a dict."""
    _, kwargs = manager.post.call_args
    return dict(parse_qsl(kwargs["data"], keep_blank_values=True))


# ---------------------------------------------------------------------------
# Credential modes + subject_token_type mapping + scope
# ---------------------------------------------------------------------------


def test_pat_mode_body_and_scope():
    manager = _ok_manager("https://app.example.com/render#code=ABC123")
    es = EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        pat="my-pat-value",
        account="myaccount",
        token_endpoint=ENDPOINT,
        session_manager=manager,
    )
    body = _posted_body(manager)
    assert body["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert body["subject_token"] == "my-pat-value"
    assert body["subject_token_type"] == SUBJECT_TOKEN_TYPE_PAT
    assert body["scope"] == f"session:streamlit:{STREAMLIT_ID}"
    # The endpoint and headers are correct.
    args, kwargs = manager.post.call_args
    assert args[0] == ENDPOINT
    assert kwargs["headers"]["Content-Type"].startswith(
        "application/x-www-form-urlencoded"
    )
    assert kwargs["headers"]["Accept"] == "application/json"
    # The streamlit embed token-exchange path has NO OAuth client identity, so the
    # request must carry no Authorization (or any other auth) header. Guard against
    # a regression that adds one.
    assert "Authorization" not in kwargs["headers"]
    assert set(kwargs["headers"]) == {"Content-Type", "Accept"}
    assert es.expires_in == 3600


def test_conn_mode_pulls_token_and_host():
    manager = _ok_manager("https://app.example.com/render#code=XYZ")
    conn = mock.MagicMock()
    conn.rest.token = "session-token-secret"
    conn.host = "acct.snowflakecomputing.com"
    conn._session_manager = manager

    EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(conn=conn)

    body = _posted_body(manager)
    assert body["subject_token"] == "session-token-secret"
    assert body["subject_token_type"] == SUBJECT_TOKEN_TYPE_SESSION
    # Default endpoint built from conn.host.
    args, _ = manager.post.call_args
    assert args[0] == "https://acct.snowflakecomputing.com/oauth/token"


def test_key_pair_mode_default_jwt_type():
    from test.unit.test_auth_keypair import generate_rsa_key_pair

    private_key_der, _ = generate_rsa_key_pair(2048)
    manager = _ok_manager("https://app.example.com/render#code=JWT1")

    EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        key_pair=private_key_der,
        account="myaccount",
        user="myuser",
        token_endpoint=ENDPOINT,
        session_manager=manager,
    )
    body = _posted_body(manager)
    # Provisional default subject_token_type for key-pair mode.
    assert body["subject_token_type"] == SUBJECT_TOKEN_TYPE_JWT
    # The minted JWT is a non-empty 3-part token, not the raw key.
    assert body["subject_token"].count(".") == 2


def test_key_pair_mode_subject_token_type_override():
    from test.unit.test_auth_keypair import generate_rsa_key_pair

    private_key_der, _ = generate_rsa_key_pair(2048)
    manager = _ok_manager("https://app.example.com/render#code=JWT2")

    EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        key_pair=private_key_der,
        account="myaccount",
        user="myuser",
        subject_token_type="urn:custom:type",
        token_endpoint=ENDPOINT,
        session_manager=manager,
    )
    assert _posted_body(manager)["subject_token_type"] == "urn:custom:type"


def test_explicit_subject_token_escape_hatch():
    manager = _ok_manager("https://app.example.com/render#code=E1")
    EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        subject_token="opaque-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        token_endpoint=ENDPOINT,
        session_manager=manager,
    )
    body = _posted_body(manager)
    assert body["subject_token"] == "opaque-token"
    assert body["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"


# ---------------------------------------------------------------------------
# redirect_uri code extraction (fragment vs query) + URL assembly
# ---------------------------------------------------------------------------


def _assert_embed_url(url, *, expected_code, expected_base_path):
    parts = urlsplit(url)
    # Code is carried in the fragment.
    assert parts.fragment == f"code={expected_code}"
    assert parts.path == expected_base_path
    qs = parse_qs(parts.query, keep_blank_values=True)
    # parentOrigin is url-encoded and round-trips.
    assert qs["__parentOrigin"] == [PARENT_ORIGIN]
    assert qs["__embeddedApp"] == ["true"]
    # The raw query must contain the encoded origin (":" and "/" escaped).
    assert "__parentOrigin=https%3A%2F%2Fanalytics.example.com" in parts.query
    # The code must not leak into the query.
    assert "code=" not in parts.query


def test_code_extracted_from_fragment():
    manager = _ok_manager("https://app.example.com/render#code=FRAGCODE")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    _assert_embed_url(url, expected_code="FRAGCODE", expected_base_path="/render")


def test_code_extracted_from_query():
    manager = _ok_manager("https://app.example.com/render?code=QUERYCODE")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    _assert_embed_url(url, expected_code="QUERYCODE", expected_base_path="/render")


def test_code_extracted_from_query_ampersand_form():
    manager = _ok_manager("https://app.example.com/render?foo=bar&code=AMPCODE")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    parts = urlsplit(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    # Pre-existing non-managed query params are preserved.
    assert qs["foo"] == ["bar"]
    assert qs["__embeddedApp"] == ["true"]
    assert parts.fragment == "code=AMPCODE"
    assert "code=AMPCODE" not in parts.query


def test_fragment_preferred_over_query():
    # If both are present, fragment wins.
    manager = _ok_manager("https://app.example.com/render?code=FROMQUERY#code=FROMFRAG")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    assert urlsplit(url).fragment == "code=FROMFRAG"


def test_base_with_existing_query_appends_managed_params():
    # redirect_uri already carries a query param AND the code in the fragment.
    manager = _ok_manager("https://app.example.com/render?tab=2#code=C9")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    parts = urlsplit(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    assert qs["tab"] == ["2"]
    assert qs["__parentOrigin"] == [PARENT_ORIGIN]
    assert qs["__embeddedApp"] == ["true"]
    assert parts.fragment == "code=C9"


def test_preexisting_managed_params_are_stripped_and_rebuilt():
    # If the server echoes __embeddedApp/__parentOrigin we must drop and re-add them
    # (no duplicates).
    manager = _ok_manager(
        "https://app.example.com/render?__embeddedApp=false"
        "&__parentOrigin=https%3A%2F%2Fevil.example.com#code=CC"
    )
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    parts = urlsplit(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    # Exactly one value each, and the caller's parent_origin wins.
    assert qs["__embeddedApp"] == ["true"]
    assert qs["__parentOrigin"] == [PARENT_ORIGIN]
    assert "evil.example.com" not in url


# A base64/base64url authorization code may contain '+', '/', and '='. The code
# carrier (fragment per the GS system function) is NOT form-encoded, so the
# extractor must read it verbatim and must NOT turn '+' into a space.
_BASE64_CODE = "aB+c/dEf12+/=="


def test_code_with_base64_special_chars_from_fragment_roundtrips_verbatim():
    manager = _ok_manager(f"https://app.example.com/render#code={_BASE64_CODE}")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    # The fragment must carry the code byte-for-byte: no '+' -> ' ' corruption.
    assert urlsplit(url).fragment == f"code={_BASE64_CODE}"
    assert " " not in urlsplit(url).fragment


def test_code_with_base64_special_chars_from_query_roundtrips_verbatim():
    # Same code, this time delivered via the query (after another param).
    manager = _ok_manager(f"https://app.example.com/render?tab=2&code={_BASE64_CODE}")
    url = (
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN)
        .prepare(pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager)
        .get_embed_url()
    )
    parts = urlsplit(url)
    # Code moves to the fragment, verbatim; the unrelated query param is preserved.
    assert parts.fragment == f"code={_BASE64_CODE}"
    assert " " not in parts.fragment
    assert parse_qs(parts.query, keep_blank_values=True)["tab"] == ["2"]


# ---------------------------------------------------------------------------
# expires_in coercion
# ---------------------------------------------------------------------------


def test_expires_in_string_is_coerced_to_int():
    manager = _ok_manager("https://app.example.com/render#code=C", expires_in="900")
    es = EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
    )
    assert es.expires_in == 900
    assert isinstance(es.expires_in, int)


def test_expires_in_non_numeric_falls_back_to_none():
    manager = _ok_manager("https://app.example.com/render#code=C", expires_in="soon")
    es = EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
    )
    assert es.expires_in is None


def test_expires_in_missing_is_none():
    manager = _fake_manager(
        _FakeResponse(
            status_code=200,
            payload={"redirect_uri": "https://app.example.com/render#code=C"},
        )
    )
    es = EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
    )
    assert es.expires_in is None


# ---------------------------------------------------------------------------
# Error / validation cases
# ---------------------------------------------------------------------------


def test_missing_credential_raises():
    with pytest.raises(ProgrammingError, match="A credential is required"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            account="a",
            token_endpoint=ENDPOINT,
            session_manager=_ok_manager("x#code=y"),
        )


def test_multiple_credentials_raises():
    with pytest.raises(ProgrammingError, match="Exactly one credential source"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p",
            subject_token="t",
            subject_token_type="urn:x",
            token_endpoint=ENDPOINT,
            session_manager=_ok_manager("x#code=y"),
        )


def test_non_200_raises_without_leaking_body():
    manager = _fake_manager(_FakeResponse(status_code=403, payload={"secret": "leak"}))
    with pytest.raises(ProgrammingError) as ei:
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
        )
    assert "403" in str(ei.value)
    assert "leak" not in str(ei.value)


def test_missing_redirect_uri_raises():
    manager = _fake_manager(_FakeResponse(status_code=200, payload={"expires_in": 60}))
    with pytest.raises(ProgrammingError, match="missing 'redirect_uri'"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
        )


def test_non_json_response_raises():
    manager = _fake_manager(_FakeResponse(status_code=200, raise_on_json=True))
    with pytest.raises(ProgrammingError, match="non-JSON"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
        )


def test_redirect_uri_without_code_raises():
    manager = _ok_manager("https://app.example.com/render")
    with pytest.raises(ProgrammingError, match="Could not find authorization code"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p", account="a", token_endpoint=ENDPOINT, session_manager=manager
        )


def test_streamlit_id_with_colon_rejected():
    with pytest.raises(ProgrammingError, match="must not contain ':'"):
        EmbeddedStreamlit("db.schema:app", PARENT_ORIGIN)


def test_empty_streamlit_id_rejected():
    with pytest.raises(ProgrammingError, match="streamlit_id"):
        EmbeddedStreamlit("", PARENT_ORIGIN)


def test_empty_parent_origin_rejected():
    with pytest.raises(ProgrammingError, match="parent_origin"):
        EmbeddedStreamlit(STREAMLIT_ID, "")


def test_get_embed_url_before_prepare_raises():
    with pytest.raises(ProgrammingError, match="before prepare"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).get_embed_url()


def test_conn_without_token_raises():
    conn = mock.MagicMock()
    conn.rest.token = None
    with pytest.raises(ProgrammingError, match="no active session token"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            conn=conn, token_endpoint=ENDPOINT, session_manager=_ok_manager("x#code=y")
        )


def test_no_endpoint_resolvable_raises():
    # PAT mode with neither token_endpoint, host, nor account => cannot resolve endpoint.
    with pytest.raises(ProgrammingError, match="resolve the token endpoint"):
        EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
            pat="p", session_manager=_ok_manager("x#code=y")
        )


def test_pat_mode_host_builds_default_endpoint_from_account():
    manager = _ok_manager("https://app.example.com/render#code=H1")
    EmbeddedStreamlit(STREAMLIT_ID, PARENT_ORIGIN).prepare(
        pat="p", account="myacct", session_manager=manager
    )
    args, _ = manager.post.call_args
    # construct_hostname(None, "myacct") -> myacct.snowflakecomputing.com
    assert args[0] == "https://myacct.snowflakecomputing.com/oauth/token"
