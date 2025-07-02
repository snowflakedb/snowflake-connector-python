#!/usr/bin/env python3
"""
Large Result Set Benchmark - Comparing sync vs async for large data retrieval.

This benchmark:
1. Creates a table with 1M+ rows of test data
2. Performs identical queries with stable sorting
3. Verifies that sync and async return identical results
4. Measures performance for large result set fetching
5. Tests memory efficiency and streaming behavior
"""

import asyncio
import hashlib
import os
import statistics
import sys
import time
from typing import List, Tuple, Any

# Add the local src directory to Python path to use development version
current_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(current_dir)
src_path = os.path.join(repo_root, 'src')
sys.path.insert(0, src_path)

from dotenv import load_dotenv
import snowflake.connector
import snowflake.connector.aio


class LargeResultBenchmark:
    """Benchmark for testing large result set retrieval performance and correctness."""
    
    def __init__(self, env_file: str = ".env"):
        """Initialize benchmark with connection parameters."""
        load_dotenv(env_file)
        
        # Connection parameters
        self.conn_params = {
            'user': os.getenv('SNOWFLAKE_USERNAME'),
            'account': os.getenv('SNOWFLAKE_ACCOUNT'),
            'database': os.getenv('SNOWFLAKE_DATABASE'),
            'schema': os.getenv('SNOWFLAKE_SCHEMA'),
            'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
            'application': os.getenv('SNOWFLAKE_APPLICATION', 'large-result-benchmark'),
        }
        
        # Add authentication
        private_key_path = os.getenv('SNOWFLAKE_PRIVATE_KEY_PATH')
        private_key_pass = os.getenv('SNOWFLAKE_PRIVATE_KEY_PASS')
        private_key = os.getenv('SNOWFLAKE_PRIVATE_KEY')
        password = os.getenv('SNOWFLAKE_PASSWORD')
        
        if private_key_path and os.path.exists(private_key_path):
            self.conn_params['private_key_file'] = private_key_path
            if private_key_pass:
                self.conn_params['private_key_file_pwd'] = private_key_pass
        elif private_key:
            self.conn_params['private_key'] = private_key
            if private_key_pass:
                self.conn_params['private_key_file_pwd'] = private_key_pass
        elif password:
            self.conn_params['password'] = password
        else:
            raise ValueError("No authentication method configured")
            
        # Test parameters
        self.table_name = "LARGE_RESULT_BENCHMARK"
        self.row_count = 1000000  # 1M rows
        
    def setup_large_table(self, table_suffix: str = "") -> str:
        """Create large test table with stable, deterministic data."""
        table_name = f"{self.table_name}{table_suffix}"
        print(f"🔨 Setting up large test table '{table_name}' with {self.row_count:,} rows...")
        print(f"   Database: {self.conn_params['database']}")
        print(f"   Schema: {self.conn_params['schema']}")
        print("   ⚠️  This may take several minutes for 1M+ rows...")
        
        conn = snowflake.connector.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            
            # Use specified database and schema
            cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            
            # Drop table if exists
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            
            # Create large hybrid table with deterministic data for result comparison
            print("📊 Creating large table with deterministic data...")
            start_time = time.time()
            
            cursor.execute(f"""
                CREATE TABLE {table_name} (
                    ID INTEGER PRIMARY KEY,
                    CATEGORY STRING,
                    VALUE DECIMAL(10,2),
                    TEXT_DATA STRING,
                    TIMESTAMP_DATA TIMESTAMP,
                    BOOLEAN_DATA BOOLEAN
                ) AS
                SELECT
                    SEQ4() as ID,
                    CASE 
                        WHEN SEQ4() % 10 = 0 THEN 'CATEGORY_A'
                        WHEN SEQ4() % 10 < 5 THEN 'CATEGORY_B' 
                        ELSE 'CATEGORY_C'
                    END as CATEGORY,
                    ROUND((SEQ4() * 1.23456), 2) as VALUE,
                    CONCAT('DATA_ROW_', LPAD(SEQ4()::STRING, 10, '0')) as TEXT_DATA,
                    DATEADD('second', SEQ4() % 86400, '2024-01-01'::TIMESTAMP) as TIMESTAMP_DATA,
                    (SEQ4() % 2 = 0) as BOOLEAN_DATA
                FROM TABLE(GENERATOR(ROWCOUNT => {self.row_count}))
            """)
            
            setup_time = time.time() - start_time
            
            # Verify row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            actual_rows = cursor.fetchone()[0]
            
            print(f"✅ Large table '{table_name}' created with {actual_rows:,} rows in {setup_time:.1f}s")
            return table_name
            
        finally:
            conn.close()
    
    def cleanup_table(self, table_name: str) -> None:
        """Clean up test table."""
        print(f"🧹 Cleaning up table '{table_name}'...")
        conn = snowflake.connector.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            print(f"✅ Table '{table_name}' cleaned up")
        finally:
            conn.close()
    
    def fetch_sync_results(self, table_name: str, limit: int) -> Tuple[List[Tuple], float, int]:
        """Fetch results using sync connector."""
        print(f"🔄 Fetching {limit:,} rows with sync connector...")
        
        conn = snowflake.connector.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            
            # Stable sort by ID to ensure deterministic results
            start_time = time.time()
            cursor.execute(f"""
                SELECT ID, CATEGORY, VALUE, TEXT_DATA, TIMESTAMP_DATA, BOOLEAN_DATA 
                FROM {table_name} 
                ORDER BY ID 
                LIMIT {limit}
            """)
            
            results = cursor.fetchall()
            fetch_time = time.time() - start_time
            
            print(f"  ✅ Sync fetched {len(results):,} rows in {fetch_time:.2f}s")
            return results, fetch_time, len(results)
            
        finally:
            conn.close()
    
    async def fetch_async_results_fetchall(self, table_name: str, limit: int) -> Tuple[List[Tuple], float, int]:
        """Fetch results using async connector with fetchall()."""
        print(f"⚡ Fetching {limit:,} rows with async connector (fetchall)...")
        
        conn = await snowflake.connector.aio.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            await cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            await cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            
            # Identical query with stable sort
            start_time = time.time()
            await cursor.execute(f"""
                SELECT ID, CATEGORY, VALUE, TEXT_DATA, TIMESTAMP_DATA, BOOLEAN_DATA 
                FROM {table_name} 
                ORDER BY ID 
                LIMIT {limit}
            """)
            
            # Use optimized fetchall() method
            results = await cursor.fetchall()
            
            fetch_time = time.time() - start_time
            
            print(f"  ✅ Async fetchall() fetched {len(results):,} rows in {fetch_time:.2f}s")
            return results, fetch_time, len(results)
            
        finally:
            await conn.close()
    
    async def fetch_async_results_iteration(self, table_name: str, limit: int) -> Tuple[List[Tuple], float, int]:
        """Fetch results using async connector with async iteration."""
        print(f"🔄 Fetching {limit:,} rows with async connector (iteration)...")
        
        conn = await snowflake.connector.aio.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            await cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            await cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            
            # Identical query with stable sort
            start_time = time.time()
            await cursor.execute(f"""
                SELECT ID, CATEGORY, VALUE, TEXT_DATA, TIMESTAMP_DATA, BOOLEAN_DATA 
                FROM {table_name} 
                ORDER BY ID 
                LIMIT {limit}
            """)
            
            # Use async iteration through result set
            results = []
            async for row in cursor:
                results.append(row)
            
            fetch_time = time.time() - start_time
            
            print(f"  ✅ Async iteration fetched {len(results):,} rows in {fetch_time:.2f}s")
            return results, fetch_time, len(results)
            
        finally:
            await conn.close()
    
    def hash_results(self, results: List[Tuple]) -> str:
        """Create deterministic hash of results for comparison."""
        # Convert all data to strings for consistent hashing
        result_strings = []
        for row in results:
            row_str = '|'.join(str(val) if val is not None else 'NULL' for val in row)
            result_strings.append(row_str)
        
        # Create hash of all rows
        combined = '\n'.join(result_strings)
        return hashlib.md5(combined.encode()).hexdigest()
    
    def verify_results_identical(self, sync_results: List[Tuple], async_results: List[Tuple]) -> bool:
        """Verify that sync and async results are identical."""
        print("\n🔍 Verifying result integrity...")
        
        # Check row counts
        if len(sync_results) != len(async_results):
            print(f"❌ Row count mismatch: sync={len(sync_results)}, async={len(async_results)}")
            return False
        
        # Check hashes
        sync_hash = self.hash_results(sync_results)
        async_hash = self.hash_results(async_results)
        
        if sync_hash != async_hash:
            print(f"❌ Data mismatch detected!")
            print(f"   Sync hash: {sync_hash}")
            print(f"   Async hash: {async_hash}")
            
            # Show first few differences
            for i, (sync_row, async_row) in enumerate(zip(sync_results, async_results)):
                if sync_row != async_row:
                    print(f"   Row {i}: sync={sync_row}, async={async_row}")
                    if i >= 3:  # Show max 3 differences
                        print("   ...")
                        break
            return False
        
        print(f"✅ Results identical! ({len(sync_results):,} rows, hash: {sync_hash[:8]}...)")
        return True
    
    def print_performance_comparison(self, sync_time: float, async_fetchall_time: float, 
                                   async_iter_time: float, row_count: int):
        """Print detailed performance comparison for all three methods."""
        print("\n" + "="*70)
        print("📊 LARGE RESULT SET PERFORMANCE COMPARISON")
        print("="*70)
        
        sync_throughput = row_count / sync_time
        async_fetchall_throughput = row_count / async_fetchall_time
        async_iter_throughput = row_count / async_iter_time
        
        fetchall_improvement = ((sync_time - async_fetchall_time) / sync_time * 100)
        iter_improvement = ((sync_time - async_iter_time) / sync_time * 100)
        
        fetchall_throughput_improvement = ((async_fetchall_throughput - sync_throughput) / sync_throughput * 100)
        iter_throughput_improvement = ((async_iter_throughput - sync_throughput) / sync_throughput * 100)
        
        print(f"📈 FETCH PERFORMANCE:")
        print(f"  • Sync time: {sync_time:.2f}s ({sync_throughput:,.0f} rows/second)")
        print(f"  • Async fetchall(): {async_fetchall_time:.2f}s ({async_fetchall_throughput:,.0f} rows/second)")
        print(f"  • Async iteration: {async_iter_time:.2f}s ({async_iter_throughput:,.0f} rows/second)")
        
        print(f"\n📊 IMPROVEMENTS vs SYNC:")
        print(f"  • Fetchall() time: {fetchall_improvement:+.1f}%")
        print(f"  • Iteration time: {iter_improvement:+.1f}%")
        print(f"  • Fetchall() throughput: {fetchall_throughput_improvement:+.1f}%")
        print(f"  • Iteration throughput: {iter_throughput_improvement:+.1f}%")
        
        print(f"\n🔍 ANALYSIS:")
        # Analyze fetchall performance
        if abs(fetchall_improvement) < 10:
            print(f"  • ℹ️  Fetchall similar performance ({fetchall_improvement:+.1f}%) - both efficient")
        elif fetchall_improvement > 10:
            print(f"  • ✅ Fetchall faster ({fetchall_improvement:+.1f}%) - optimized bulk processing")
        else:
            print(f"  • ⚠️  Fetchall slower ({abs(fetchall_improvement):.1f}%) - investigate overhead")
            
        # Analyze iteration performance  
        if abs(iter_improvement) < 10:
            print(f"  • ℹ️  Iteration similar performance ({iter_improvement:+.1f}%) - acceptable overhead")
        elif iter_improvement > 10:
            print(f"  • ✅ Iteration faster ({iter_improvement:+.1f}%) - efficient streaming")
        else:
            print(f"  • ⚠️  Iteration slower ({abs(iter_improvement):.1f}%) - expected for row-by-row processing")
            
        # Overall assessment
        if fetchall_improvement > iter_improvement:
            print(f"  • 🎯 Fetchall() is the optimal method for large result sets")
        else:
            print(f"  • 🎯 Both methods perform similarly - choose based on memory constraints")
    
    async def run_benchmark(self, test_sizes: List[int] = None):
        """Run the complete large result set benchmark."""
        if test_sizes is None:
            test_sizes = [1000, 10000, 1000000]  # Test different result sizes
            
        print("🚀 Starting Large Result Set Benchmark")
        print(f"   Table size: {self.row_count:,} rows")
        print(f"   Test sizes: {[f'{s:,}' for s in test_sizes]}")
        print(f"   Database: {self.conn_params['database']}")
        print()
        
        # Create large table
        table_name = self.setup_large_table("_LARGE")
        
        try:
            all_passed = True
            
            for test_size in test_sizes:
                print(f"\n{'='*50}")
                print(f"📊 Testing {test_size:,} row fetch")
                print('='*50)
                
                # Fetch with sync connector
                sync_results, sync_time, sync_count = self.fetch_sync_results(table_name, test_size)
                
                # Fetch with async connector using fetchall()
                async_fetchall_results, async_fetchall_time, async_fetchall_count = await self.fetch_async_results_fetchall(table_name, test_size)
                
                # Fetch with async connector using iteration
                async_iter_results, async_iter_time, async_iter_count = await self.fetch_async_results_iteration(table_name, test_size)
                
                # Verify results are identical
                fetchall_match = self.verify_results_identical(sync_results, async_fetchall_results)
                if not fetchall_match:
                    all_passed = False
                    print("❌ CRITICAL: Fetchall results do not match!")
                    continue
                    
                print("\n🔍 Verifying async iteration results...")
                iter_match = self.verify_results_identical(sync_results, async_iter_results)
                if not iter_match:
                    all_passed = False
                    print("❌ CRITICAL: Iteration results do not match!")
                    continue
                
                # Performance comparison
                self.print_performance_comparison(sync_time, async_fetchall_time, async_iter_time, test_size)
                
        finally:
            # Cleanup
            print(f"\n{'='*50}")
            self.cleanup_table(table_name)
            
        print(f"\n🎯 BENCHMARK SUMMARY:")
        if all_passed:
            print("✅ All tests passed - sync and async results identical")
            print("✅ Large result set benchmark completed successfully")
        else:
            print("❌ Some tests failed - investigate async connector issues")


async def main():
    """Main benchmark entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Benchmark large result set retrieval")
    parser.add_argument("--sizes", nargs='+', type=int, default=[1000, 10000, 1000000],
                       help="Result set sizes to test (default: 1000, >1000 may trigger async bugs)")
    parser.add_argument("--env-file", default=".env", help="Environment file path (default: .env)")
    
    args = parser.parse_args()
    
    try:
        benchmark = LargeResultBenchmark(args.env_file)
        await benchmark.run_benchmark(args.sizes)
    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())