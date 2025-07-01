"""
Integration tests for async Snowflake connector private key authentication.

These tests verify the async keypair authentication functionality.
"""

import os
import pytest
from pathlib import Path

# Skip tests if aiohttp not available
pytest_plugins = []
try:
    import aiohttp
    aiohttp_available = True
except ImportError:
    aiohttp_available = False


@pytest.mark.skipif(not aiohttp_available, reason="aiohttp not available")
class TestAsyncKeyPairAuth:
    """Test async private key authentication functionality."""
    
    def _get_keypair_connection_params(self) -> dict | None:
        """Get connection parameters for keypair authentication from environment."""
        user = os.getenv('SNOWFLAKE_USER')
        account = os.getenv('SNOWFLAKE_ACCOUNT') 
        private_key_file = os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE')
        private_key_file_pwd = os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE_PWD')
        
        if not all([user, account, private_key_file]):
            return None
            
        # Check if private key file exists
        if not Path(private_key_file).exists():
            return None
            
        return {
            'user': user,
            'account': account,
            'private_key_file': private_key_file,
            'private_key_file_pwd': private_key_file_pwd,
            'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
            'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
            'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
        }
    
    @pytest.mark.asyncio
    async def test_keypair_connection(self):
        """Test basic async connection with private key authentication."""
        conn_params = self._get_keypair_connection_params()
        if not conn_params:
            pytest.skip("Keypair connection parameters not available")
            
        # Import here to avoid import errors when aiohttp not available
        import snowflake.connector.aio
        
        conn = None
        try:
            # Test async connection with keypair auth
            conn = await snowflake.connector.aio.connect(**conn_params)
            
            # Verify connection properties
            assert not conn.is_closed()
            assert conn.user == conn_params['user']
            assert conn.account == conn_params['account']
            
        finally:
            if conn:
                await conn.close()
                
    @pytest.mark.asyncio 
    async def test_keypair_execute(self):
        """Test basic async query execution with keypair auth."""
        conn_params = self._get_keypair_connection_params()
        if not conn_params:
            pytest.skip("Keypair connection parameters not available")
            
        import snowflake.connector.aio
        
        conn = None
        try:
            conn = await snowflake.connector.aio.connect(**conn_params)
            
            # Test basic query execution via cursor
            cursor = conn.cursor()
            await cursor.execute("SELECT 1 as test_col")
            
            # Verify cursor state
            assert not cursor.is_closed()
            assert cursor.sfqid is not None  # Should have query ID
            
            # Test fetching results
            row = await cursor.fetchone()
            assert row is not None
            
        finally:
            if conn:
                await conn.close()
                
    @pytest.mark.asyncio
    async def test_keypair_auth_object_creation(self):
        """Test that keypair auth objects can be created independently."""
        from snowflake.connector.aio.auth import AsyncAuthByKeyPair
        
        # Test with dummy key data (won't authenticate but should create object)
        dummy_key = b"dummy_key_data"
        
        auth = AsyncAuthByKeyPair(private_key=dummy_key)
        
        # Verify auth object properties
        assert auth is not None
        assert hasattr(auth, 'prepare')
        assert hasattr(auth, 'update_body')
        assert hasattr(auth, 'assertion_content')
        
    def test_keypair_auth_import(self):
        """Test that keypair auth can be imported without issues."""
        # This test verifies the module structure is correct
        try:
            from snowflake.connector.aio.auth import AsyncAuthByKeyPair
            from snowflake.connector.aio.auth import AsyncAuthByDefault
            assert AsyncAuthByKeyPair is not None
            assert AsyncAuthByDefault is not None
        except ImportError as e:
            pytest.fail(f"Failed to import async auth classes: {e}")
            
    @pytest.mark.asyncio
    async def test_auth_composition_pattern(self):
        """Test that async auth properly composes sync auth."""
        from snowflake.connector.aio.auth import AsyncAuthByKeyPair
        from snowflake.connector.auth.keypair import AuthByKeyPair
        
        dummy_key = b"dummy_key_data"
        async_auth = AsyncAuthByKeyPair(private_key=dummy_key)
        
        # Verify composition - async auth should have sync auth internally
        assert hasattr(async_auth, '_sync_auth')
        assert isinstance(async_auth._sync_auth, AuthByKeyPair)
        
        # Verify properties delegate correctly
        assert async_auth.type_ == async_auth._sync_auth.type_