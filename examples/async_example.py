#!/usr/bin/env python3
"""
Example usage of Snowflake async connector.

This demonstrates the basic usage patterns for the async Snowflake connector
and shows the benefits of true async I/O for concurrent query execution.
"""

import asyncio
import os
import time
from typing import Optional


async def basic_async_example():
    """Basic async connection and query execution."""
    print("=== Basic Async Example ===")
    
    try:
        import snowflake.connector.aio
    except ImportError as e:
        print(f"Error: {e}")
        print("Install with: pip install snowflake-connector-python-async")
        return
        
    # Connection parameters - set these environment variables
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'password': os.getenv('SNOWFLAKE_PASSWORD'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    if not all([conn_params['user'], conn_params['password'], conn_params['account']]):
        print("Please set SNOWFLAKE_USER, SNOWFLAKE_PASSWORD, and SNOWFLAKE_ACCOUNT environment variables")
        return
        
    conn = None
    try:
        # Establish async connection
        print("Connecting to Snowflake...")
        conn = await snowflake.connector.aio.connect(**conn_params)
        print(f"Connected as {conn.user} to account {conn.account}")
        
        # Execute simple query using cursor (proper DB-API 2.0 pattern)
        print("\\nExecuting query...")
        cursor = conn.cursor()
        await cursor.execute("SELECT 1 as test_column")
        print(f"Query executed, Query ID: {cursor.sfqid}")
        
        # Fetch results
        row = await cursor.fetchone()
        print(f"First row: {row}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            await conn.close()
            print("Connection closed")


async def concurrent_queries_example():
    """Demonstrate concurrent query execution - the main benefit of async."""
    print("\\n=== Concurrent Queries Example ===")
    
    try:
        import snowflake.connector.aio
    except ImportError as e:
        print(f"Error: {e}")
        return
        
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'password': os.getenv('SNOWFLAKE_PASSWORD'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    if not all([conn_params['user'], conn_params['password'], conn_params['account']]):
        print("Connection parameters not available")
        return
        
    conn = None
    try:
        conn = await snowflake.connector.aio.connect(**conn_params)
        
        # Define multiple queries to run concurrently
        queries = [
            "SELECT 1 as query_1, CURRENT_TIMESTAMP() as ts",
            "SELECT 2 as query_2, CURRENT_TIMESTAMP() as ts", 
            "SELECT 3 as query_3, CURRENT_TIMESTAMP() as ts",
            "SELECT COUNT(*) as table_count FROM INFORMATION_SCHEMA.TABLES",
            "SELECT CURRENT_USER() as current_user",
        ]
        
        print(f"Executing {len(queries)} queries concurrently...")
        start_time = time.time()
        
        # Execute all queries concurrently using cursors - this is the async advantage!
        async def execute_single_query(query):
            cursor = conn.cursor()
            await cursor.execute(query)
            return cursor
            
        cursors = await asyncio.gather(*[
            execute_single_query(query) for query in queries
        ])
        
        elapsed = time.time() - start_time
        print(f"All {len(queries)} queries completed in {elapsed:.2f} seconds")
        
        # Print results
        for i, cursor in enumerate(cursors, 1):
            row = await cursor.fetchone()
            print(f"Query {i} first row: {row}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            await conn.close()


async def sqlalchemy_compatible_example():
    """Example showing SQLAlchemy-compatible interface patterns."""
    print("\\n=== SQLAlchemy-Compatible Interface Example ===")
    
    try:
        import snowflake.connector.aio
    except ImportError as e:
        print(f"Error: {e}")
        return
        
    conn_params = {
        'user': os.getenv('SNOWFLAKE_USER'),
        'password': os.getenv('SNOWFLAKE_PASSWORD'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'database': os.getenv('SNOWFLAKE_DATABASE', 'SNOWFLAKE_SAMPLE_DATA'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA', 'INFORMATION_SCHEMA'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    }
    
    if not all([conn_params['user'], conn_params['password'], conn_params['account']]):
        print("Connection parameters not available")
        return
        
    conn = None
    try:
        conn = await snowflake.connector.aio.connect(**conn_params)
        
        # SQLAlchemy AsyncConnection-style usage
        print("Using SQLAlchemy-compatible interface...")
        
        # Execute with parameters using cursor
        cursor = conn.cursor()
        await cursor.execute("SELECT ? as param_value", (42,))
        row = await cursor.fetchone()
        print(f"Parameterized query result: {row}")
        
        # Transaction control
        print("Testing transaction control...")
        cursor = conn.cursor()
        await cursor.execute("BEGIN")
        # In a real scenario, you'd do some DML operations here
        await conn.rollback()
        print("Transaction rolled back successfully")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            await conn.close()


async def main():
    """Run all examples."""
    print("Snowflake Async Connector Examples")
    print("=" * 40)
    
    await basic_async_example()
    await concurrent_queries_example() 
    await sqlalchemy_compatible_example()
    
    print("\\n=== Examples Complete ===")
    print("Next steps:")
    print("1. Try running multiple queries concurrently")
    print("2. Compare performance with sync connector")
    print("3. Integrate with async web frameworks like FastAPI")
    print("4. Try private key authentication - see async_keypair_example.py")


if __name__ == "__main__":
    # Run the async examples
    asyncio.run(main())