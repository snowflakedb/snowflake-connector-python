"""
Integration tests for async Snowflake connector using aiohttp.

These tests verify the basic functionality of the async connector while
demonstrating its usage patterns.
"""

import asyncio
import pytest
import os
from typing import Optional

# Skip tests if aiohttp not available
pytest_plugins = []
try:
    import aiohttp
    aiohttp_available = True
except ImportError:
    aiohttp_available = False


@pytest.mark.skipif(not aiohttp_available, reason="aiohttp not available")
class TestAsyncConnection:
    """Test async connection functionality."""
    
    def _get_connection_params(self) -> Optional[dict]:
        """Get connection parameters from environment variables."""
        user = os.getenv('SNOWFLAKE_USER')
        password = os.getenv('SNOWFLAKE_PASSWORD') 
        account = os.getenv('SNOWFLAKE_ACCOUNT')
        
        if not all([user, password, account]):
            return None
            
        return {
            'user': user,
            'password': password,
            'account': account,
            'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
            'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
            'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
        }
    
    @pytest.mark.asyncio
    async def test_basic_connection(self):
        """Test basic async connection establishment."""
        conn_params = self._get_connection_params()
        if not conn_params:
            pytest.skip("Connection parameters not available")
            
        # Import here to avoid import errors when aiohttp not available
        import snowflake.connector.aio
        
        conn = None
        try:
            # Test async connection
            conn = await snowflake.connector.aio.connect(**conn_params)
            
            # Verify connection properties
            assert not conn.is_closed()
            assert conn.user == conn_params['user']
            assert conn.account == conn_params['account']
            
        finally:
            if conn:
                await conn.close()
                
    @pytest.mark.asyncio 
    async def test_basic_execute(self):
        """Test basic async query execution."""
        conn_params = self._get_connection_params()
        if not conn_params:
            pytest.skip("Connection parameters not available")
            
        import snowflake.connector.aio
        
        conn = None
        try:
            conn = await snowflake.connector.aio.connect(**conn_params)
            
            # Test basic query execution via cursor (proper DB-API 2.0 pattern)
            cursor = conn.cursor()
            await cursor.execute("SELECT 1 as test_col")
            
            # Verify cursor state
            assert not cursor.is_closed()
            assert cursor.sfqid is not None  # Should have query ID
            
        finally:
            if conn:
                await conn.close()
                
    @pytest.mark.asyncio
    async def test_concurrent_queries(self):
        """Test concurrent query execution - demonstrates async benefit."""
        conn_params = self._get_connection_params()
        if not conn_params:
            pytest.skip("Connection parameters not available")
            
        import snowflake.connector.aio
        
        conn = None
        try:
            conn = await snowflake.connector.aio.connect(**conn_params)
            
            # Execute multiple queries concurrently using cursors
            queries = [
                "SELECT 1 as col1",
                "SELECT 2 as col2", 
                "SELECT 3 as col3"
            ]
            
            # This demonstrates true async - all queries execute concurrently
            async def execute_query(query):
                cursor = conn.cursor()
                await cursor.execute(query)
                return cursor
                
            cursors = await asyncio.gather(*[
                execute_query(query) for query in queries
            ])
            
            # Verify all cursors
            assert len(cursors) == 3
            for cursor in cursors:
                assert not cursor.is_closed()
                assert cursor.sfqid is not None
                
        finally:
            if conn:
                await conn.close()
                
    @pytest.mark.asyncio
    async def test_connection_context_manager(self):
        """Test that connection can be used as async context manager (future enhancement)."""
        conn_params = self._get_connection_params()
        if not conn_params:
            pytest.skip("Connection parameters not available")
            
        import snowflake.connector.aio
        
        # For now, manual connection management
        # In future phases, will support: async with snowflake.connector.aio.connect(...) as conn:
        conn = await snowflake.connector.aio.connect(**conn_params)
        try:
            cursor = conn.cursor()
            await cursor.execute("SELECT CURRENT_TIMESTAMP() as ts")
            assert not cursor.is_closed()
        finally:
            await conn.close()
            
    def test_import_without_aiohttp(self):
        """Test that import fails gracefully without aiohttp."""
        # This test verifies graceful degradation
        import sys
        import importlib
        
        # Mock missing aiohttp
        original_aiohttp = sys.modules.get('aiohttp')
        if 'aiohttp' in sys.modules:
            del sys.modules['aiohttp']
            
        try:
            # Should raise ImportError with helpful message
            with pytest.raises(ImportError, match="aiohttp is required"):
                if 'snowflake.connector.aio.network' in sys.modules:
                    importlib.reload(sys.modules['snowflake.connector.aio.network'])
                else:
                    import snowflake.connector.aio.network
                    
        finally:
            # Restore aiohttp if it was available
            if original_aiohttp:
                sys.modules['aiohttp'] = original_aiohttp