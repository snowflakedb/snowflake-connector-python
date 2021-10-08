#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import uuid
from typing import Dict, Optional, Tuple, Union

from .connection_base import SnowflakeConnectionBase


class StoredProcConnection(SnowflakeConnectionBase):
    def __init__(self):
        super().__init__()
        pass

    def _magic_execute_sql(self, sql):
        pass

    def cmd_query(
        self,
        sql: str,
        sequence_counter: int,
        request_id: uuid.UUID,
        binding_params: Union[None, Tuple, Dict[str, Dict[str, str]]] = None,
        binding_stage: Optional[str] = None,
        is_file_transfer: bool = False,
        statement_params: Optional[Dict[str, str]] = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _update_current_object: bool = True,
    ) -> Dict:
        return {
            "data": {
                "parameters": [],
                "rowtype": [
                    {
                        "name": "COLA",
                        "database": "TESTDB",
                        "schema": "TESTSCHEMA",
                        "table": "TEST_CUSTOM_CONN_TABLE",
                        "type": "Text",
                        "length": None,
                        "precision": None,
                        "scale": None,
                        "nullable": True,
                    },
                    {
                        "name": "COLB",
                        "database": "TESTDB",
                        "schema": "TESTSCHEMA",
                        "table": "TEST_CUSTOM_CONN_TABLE",
                        "type": "fixed",
                        "length": None,
                        "precision": None,
                        "scale": None,
                        "nullable": True,
                    },
                ],
                "rowset": [["rowOne", "1"], ["rowTwo", "2"]],
                "total": 2,
                "returned": 2,
                "queryId": "0199922f-015a-7715-0000-0014000123ca",
                "databaseProvider": None,
                "finalDatabaseName": "TESTDB2",
                "finalSchemaName": "TESTSCHEMA2",
                "finalWarehouseName": "DEV",
                "finalRoleName": "SYSADMIN",
                "numberOfBinds": 0,
                "arrayBindSupported": False,
                "statementTypeId": 4096,
                "version": 1,
                "sendResultTime": 1610498856446,
                "queryResultFormat": "json",
            },
            "success": True,
        }
