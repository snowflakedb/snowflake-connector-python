from __future__ import annotations

import asyncio
from logging import getLogger

from snowflake.connector.crl import CRLValidator as CRLValidatorSync

logger = getLogger(__name__)


class CRLValidator(CRLValidatorSync):
    def _session_manager_get(self, *args, **kwargs):
        return asyncio.get_event_loop().run_until_complete(
            self._session_manager.get(*args, **kwargs)
        )
