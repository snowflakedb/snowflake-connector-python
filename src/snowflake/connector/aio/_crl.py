from __future__ import annotations

from logging import getLogger

from snowflake.connector.crl import CRLValidator as CRLValidatorSync

logger = getLogger(__name__)


class CRLValidator(CRLValidatorSync):
    async def _session_manager_get(self, *args, **kwargs):
        return await self._session_manager.get(*args, **kwargs)
