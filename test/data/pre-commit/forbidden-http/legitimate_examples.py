#!/usr/bin/env python3
"""
Example file containing legitimate code that should NOT be flagged.
This demonstrates proper usage patterns and type hint scenarios.
"""

from typing import TYPE_CHECKING, Dict, Generator, List, Optional, Tuple

# Type-only imports - should be allowed
from requests import Session
from urllib3 import PoolManager, ProxyManager

# TYPE_CHECKING guarded imports - should be allowed
if TYPE_CHECKING:
    from requests import Response
    from urllib3 import HTTPResponse


def api_function(
    session: Session, pool: PoolManager, proxy: Optional[ProxyManager] = None
) -> Generator[Session, None, None]:
    """
    Function using imports only for type hints.
    Should not trigger any violations.
    """
    yield session


def complex_type_function(
    sessions: List[Tuple[Session, int]],
    pools: Dict[str, PoolManager],
    responses: Optional[List[Response]] = None,
) -> Dict[str, List[Session]]:
    """
    Complex nested type usage.
    Should not trigger any violations.
    """
    return {}


# PEP 604 union syntax
def pep604_function(s: Session | None) -> PoolManager | str:
    """
    PEP 604 union type syntax.
    Should not trigger any violations.
    """
    pass


def response_handler(resp: Response) -> HTTPResponse:
    """
    Using TYPE_CHECKING imports in type hints.
    Should not trigger any violations.
    """
    pass


# Variable annotations with type hints
sessions_map: Dict[str, Session] = {}
pool_list: List[PoolManager] = []
optional_session: Optional[Session] = None


class APIClient:
    """Class with type-hinted attributes."""

    def __init__(self, session: Session, pool: PoolManager):
        """Constructor with type hints - should be allowed."""
        pass

    def get_session(self) -> Session:
        """Method returning Session type - should be allowed."""
        pass

    def process_pools(self, pools: List[PoolManager]) -> None:
        """Method with pool manager types - should be allowed."""
        pass
