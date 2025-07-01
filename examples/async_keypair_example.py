#!/usr/bin/env python3
"""
Example usage of Snowflake async connector with private key authentication.

This demonstrates how to use private key authentication with the async 
Snowflake connector for secure, password-less authentication.
"""

import asyncio
import os
from pathlib import Path


async def keypair_auth_example():
    """Example of async connection with private key authentication."""
    print("=== Async Private Key Authentication Example ===")
    
    try:
        import snowflake.connector.aio
    except ImportError as e:
        print(f"Error: {e}")
        print("Install with: pip install snowflake-connector-python-async")
        return
        
    # Connection parameters for private key authentication
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'private_key_file': os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE'),
        'private_key_file_pwd': os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE_PWD'),  # Optional
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    # Validate required parameters
    if not all([conn_params['user'], conn_params['account'], conn_params['private_key_file']]):
        print("Please set the following environment variables:")
        print("- SNOWFLAKE_USER")
        print("- SNOWFLAKE_ACCOUNT") 
        print("- SNOWFLAKE_PRIVATE_KEY_FILE")
        print("- SNOWFLAKE_PRIVATE_KEY_FILE_PWD (optional, if key is encrypted)")
        return
        
    # Check if private key file exists
    private_key_path = Path(conn_params['private_key_file'])
    if not private_key_path.exists():
        print(f"Private key file not found: {private_key_path}")
        print("Please ensure the private key file exists and the path is correct.")
        return
        
    conn = None
    try:
        # Establish async connection using private key authentication
        print("Connecting to Snowflake with private key authentication...")
        conn = await snowflake.connector.aio.connect(**conn_params)
        print(f"✅ Connected as {conn.user} to account {conn.account}")
        print("🔐 Using private key authentication (no password required)")
        
        # Execute query using private key authenticated connection
        print("\\nExecuting query...")
        cursor = conn.cursor()
        await cursor.execute("SELECT CURRENT_USER() as current_user, CURRENT_ACCOUNT() as current_account")
        
        # Fetch and display results
        row = await cursor.fetchone()
        if row:
            print(f"Current user: {row[0]}")
            print(f"Current account: {row[1]}")
            
        print(f"Query ID: {cursor.sfqid}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\\nTroubleshooting tips:")
        print("1. Ensure your private key file is in the correct format (PEM)")
        print("2. Verify the private key is registered with your Snowflake user")
        print("3. Check that the account and user parameters are correct")
        print("4. If using an encrypted private key, ensure the password is correct")
    finally:
        if conn:
            await conn.close()
            print("\\n🔌 Connection closed")


async def keypair_auth_with_raw_key_example():
    """Example using raw private key data instead of file."""
    print("\\n=== Private Key Authentication with Raw Key Data ===")
    
    try:
        import snowflake.connector.aio
    except ImportError:
        print("aiohttp not available")
        return
        
    # Example of loading private key from file and passing as bytes
    private_key_file = os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE')
    if not private_key_file or not Path(private_key_file).exists():
        print("Private key file not available for raw key example")
        return
        
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    if not all([conn_params['user'], conn_params['account']]):
        print("Missing required connection parameters")
        return
        
    try:
        # Load private key from file
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        private_key_pwd = os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE_PWD')
        password = private_key_pwd.encode('utf-8') if private_key_pwd else None
        
        with open(private_key_file, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
            
        # Convert to DER format (required by Snowflake)
        private_key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Use raw private key bytes instead of file
        conn_params['private_key'] = private_key_der
        
        conn = None
        try:
            print("Connecting with raw private key data...")
            conn = await snowflake.connector.aio.connect(**conn_params)
            print(f"✅ Connected using raw private key data")
            
            # Test query
            cursor = conn.cursor()
            await cursor.execute("SELECT 'Raw key auth successful' as result")
            row = await cursor.fetchone()
            print(f"Result: {row[0] if row else 'No result'}")
            
        finally:
            if conn:
                await conn.close()
                
    except Exception as e:
        print(f"❌ Error with raw key: {e}")


async def concurrent_keypair_connections_example():
    """Example of multiple concurrent connections with keypair auth."""
    print("\\n=== Concurrent Keypair Authentication Example ===")
    
    try:
        import snowflake.connector.aio
    except ImportError:
        print("aiohttp not available")
        return
        
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'private_key_file': os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE'),
        'private_key_file_pwd': os.getenv('SNOWFLAKE_PRIVATE_KEY_FILE_PWD'),
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    if not all([conn_params['user'], conn_params['account'], conn_params['private_key_file']]):
        print("Missing required connection parameters for concurrent example")
        return
        
    async def execute_query(query_id: int, query: str):
        """Execute a query on a separate connection."""
        conn = None
        try:
            conn = await snowflake.connector.aio.connect(**conn_params)
            cursor = conn.cursor()
            await cursor.execute(query)
            row = await cursor.fetchone()
            return f"Query {query_id}: {row[0] if row else 'No result'}"
        finally:
            if conn:
                await conn.close()
                
    try:
        # Execute multiple queries concurrently using keypair auth
        queries = [
            "SELECT 1 as result",
            "SELECT 2 as result", 
            "SELECT 'Concurrent keypair auth' as result",
            "SELECT CURRENT_TIMESTAMP() as result"
        ]
        
        print(f"Executing {len(queries)} queries concurrently with keypair auth...")
        
        results = await asyncio.gather(*[
            execute_query(i+1, query) for i, query in enumerate(queries)
        ])
        
        print("✅ All queries completed:")
        for result in results:
            print(f"  {result}")
            
    except Exception as e:
        print(f"❌ Error in concurrent example: {e}")


async def main():
    """Run all keypair authentication examples."""
    print("Snowflake Async Connector - Private Key Authentication Examples")
    print("=" * 65)
    
    await keypair_auth_example()
    await keypair_auth_with_raw_key_example() 
    await concurrent_keypair_connections_example()
    
    print("\\n=== Examples Complete ===")
    print("\\nPrivate Key Authentication Benefits:")
    print("✅ No password required - more secure")
    print("✅ Perfect for automated/service applications") 
    print("✅ Supports key rotation without code changes")
    print("✅ Works with all async connector features")
    print("\\nFor setup instructions, see:")
    print("https://docs.snowflake.com/en/user-guide/key-pair-auth.html")


if __name__ == "__main__":
    # Run the async examples
    asyncio.run(main())