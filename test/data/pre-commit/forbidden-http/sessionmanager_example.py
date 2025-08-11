#!/usr/bin/env python3
"""
Example of how code should look when using SessionManager.
This represents the target state after migration.
"""

from snowflake.connector.session_manager import SessionManager


# Proper SessionManager usage examples
def make_api_request(session_manager: SessionManager):
    """Example of proper HTTP request using SessionManager."""

    # Instead of: requests.get("http://example.com")
    # Use SessionManager:
    response = session_manager.request("GET", "http://example.com")
    return response


def use_session_context(session_manager: SessionManager):
    """Example of proper session usage with SessionManager."""

    # Instead of: with requests.Session() as session:
    # Use SessionManager context:
    with session_manager.use_requests_session("http://example.com") as session:
        response = session.get("/api/data")
        return response


def batch_requests(session_manager: SessionManager):
    """Example of batch requests using SessionManager."""

    # Multiple requests using the same manager
    results = []
    endpoints = ["/api/users", "/api/posts", "/api/comments"]

    for endpoint in endpoints:
        response = session_manager.request("GET", f"http://api.example.com{endpoint}")
        results.append(response.json())

    return results


def configure_session(session_manager: SessionManager):
    """Example of session configuration through SessionManager."""

    # SessionManager handles adapter mounting, timeouts, etc.
    with session_manager.use_requests_session(
        "http://example.com", use_pooling=True
    ) as session:
        # Session is pre-configured by SessionManager
        response = session.post("/api/data", json={"key": "value"})
        return response


# Type hints with SessionManager - this is the proper way
from typing import Optional


def api_client_function(manager: SessionManager) -> Optional[dict]:
    """
    Proper type hints using SessionManager instead of raw requests/urllib3.
    This is what developers should migrate to.
    """
    try:
        response = manager.request("GET", "http://api.example.com/health")
        return response.json()
    except Exception:
        return None
