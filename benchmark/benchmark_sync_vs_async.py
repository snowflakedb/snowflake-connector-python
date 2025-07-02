#!/usr/bin/env python3
"""
Benchmark script comparing sync vs async Snowflake connector performance.

This script:
1. Sets up a test table with 100,000 rows 
2. Runs parallel queries using both sync and async connectors
3. Measures and compares performance metrics
"""

import asyncio
import concurrent.futures
import os
import random
import statistics
import sys
import time
from typing import List, Tuple

# Add the local src directory to Python path to use development version
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(repo_root, 'src')
sys.path.insert(0, src_path)

import snowflake.connector
import snowflake.connector.aio
from dotenv import load_dotenv


class SnowflakeBenchmark:
    """Benchmark comparing sync vs async Snowflake connector performance."""
    
    def __init__(self, env_file: str = ".env"):
        """Initialize benchmark with credentials from env file."""
        load_dotenv(env_file)
        
        # Base connection parameters
        self.conn_params = {
            'user': os.getenv('SNOWFLAKE_USERNAME') or os.getenv('SNOWFLAKE_USER'),
            'account': os.getenv('SNOWFLAKE_ACCOUNT'),
            'database': os.getenv('SNOWFLAKE_DATABASE'),
            'schema': os.getenv('SNOWFLAKE_SCHEMA'),
            'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
            'application': os.getenv('SNOWFLAKE_APPLICATION', 'snowflake-benchmark'),
        }
        
        # Authentication - prefer private key over password
        private_key = os.getenv('SNOWFLAKE_PRIVATE_KEY')
        private_key_path = os.getenv('SNOWFLAKE_PRIVATE_KEY_PATH')
        private_key_pass = os.getenv('SNOWFLAKE_PRIVATE_KEY_PASS')
        password = os.getenv('SNOWFLAKE_PASSWORD')
        
        if private_key:
            # Use private key from environment variable
            self.conn_params['private_key'] = private_key
            if private_key_pass:
                self.conn_params['private_key_file_pwd'] = private_key_pass
        elif private_key_path:
            # Use private key from file
            self.conn_params['private_key_file'] = private_key_path
            if private_key_pass:
                self.conn_params['private_key_file_pwd'] = private_key_pass
        elif password:
            # Fall back to password authentication
            self.conn_params['password'] = password
        else:
            raise ValueError("Must provide either SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_PRIVATE_KEY_PATH, or SNOWFLAKE_PASSWORD")
        
        # Validate required parameters
        required = ['user', 'account', 'database', 'schema', 'warehouse']
        missing = [k for k in required if not self.conn_params.get(k)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")
            
        self.table_name = "BENCHMARK_TEST_TABLE"
        self.row_count = 100000
        
    def setup_test_data(self, table_suffix: str = "") -> str:
        """Create and populate test table with data in a single query.
        
        Args:
            table_suffix: Optional suffix for table name (e.g., "_SYNC", "_ASYNC")
            
        Returns:
            The full table name that was created
        """
        table_name = f"{self.table_name}{table_suffix}"
        print(f"🔨 Setting up test table '{table_name}' with {self.row_count:,} rows...")
        print(f"   Database: {self.conn_params['database']}")
        print(f"   Schema: {self.conn_params['schema']}")
        
        conn = snowflake.connector.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            
            # Use specified database and schema (must exist)
            cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            
            # Drop table if exists
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            
            # Create hybrid table with data in a single query for efficiency
            print("📊 Creating hybrid table with random data...")
            cursor.execute(f"""
                CREATE HYBRID TABLE {table_name} (
                    ID INTEGER PRIMARY KEY,
                    VAL STRING
                ) AS
                SELECT
                    SEQ4() as ID,
                    RANDSTR(50, RANDOM()) as VAL
                FROM TABLE(GENERATOR(ROWCOUNT => {self.row_count}))
            """)
            
            # Verify row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            actual_rows = cursor.fetchone()[0]
            print(f"✅ Test table '{table_name}' created with {actual_rows:,} rows")
            
            return table_name
            
        finally:
            conn.close()
    
    def cleanup_test_data(self, table_name: str) -> None:
        """Clean up test table.
        
        Args:
            table_name: Name of the table to drop
        """
        print(f"🧹 Cleaning up test table '{table_name}'...")
        conn = snowflake.connector.connect(**self.conn_params)
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE DATABASE {self.conn_params['database']}")
            cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            print(f"✅ Test table '{table_name}' cleaned up")
        finally:
            conn.close()
    
    def sync_query_worker(self, conn, table_name: str, query_id: int) -> Tuple[int, float, int]:
        """Execute a single sync query using provided connection."""
        start_time = time.time()
        
        cursor = conn.cursor()
        
        # Select random ID
        random_id = random.randint(0, self.row_count - 1)
        cursor.execute(f"SELECT ID, VAL FROM {table_name} WHERE ID = %s", (random_id,))
        
        result = cursor.fetchone()
        rows_fetched = 1 if result else 0
        cursor.close()
            
        elapsed = time.time() - start_time
        return query_id, elapsed, rows_fetched
    
    async def async_query_worker(self, conn, table_name: str, query_id: int) -> Tuple[int, float, int]:
        """Execute a single async query using provided connection."""
        start_time = time.time()
        
        cursor = conn.cursor()
        
        # Select random ID  
        random_id = random.randint(0, self.row_count - 1)
        await cursor.execute(f"SELECT ID, VAL FROM {table_name} WHERE ID = %s", (random_id,))
        
        result = await cursor.fetchone()
        rows_fetched = 1 if result else 0
        
        elapsed = time.time() - start_time
        return query_id, elapsed, rows_fetched
    
    def benchmark_sync(self, num_queries: int, max_workers: int) -> Tuple[List[float], float]:
        """Benchmark sync connector with setup/teardown per benchmark."""
        # Create table for sync benchmark
        table_name = self.setup_test_data("_SYNC")
        
        try:
            print(f"🔄 Running {num_queries} sync queries with {max_workers} threads...")
            
            # Create one connection per worker thread
            connections = {}
            
            def worker_with_connection(query_id: int):
                import threading
                thread_id = threading.get_ident()
                
                # Create connection for this thread if not exists
                if thread_id not in connections:
                    conn = snowflake.connector.connect(**self.conn_params)
                    cursor = conn.cursor()
                    cursor.execute(f"USE DATABASE {self.conn_params['database']}")
                    cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
                    cursor.close()
                    connections[thread_id] = conn
                
                return self.sync_query_worker(connections[thread_id], table_name, query_id)
            
            start_time = time.time()
            query_times = []
            
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [
                        executor.submit(worker_with_connection, i) 
                        for i in range(num_queries)
                    ]
                    
                    for future in concurrent.futures.as_completed(futures):
                        query_id, query_time, rows = future.result()
                        query_times.append(query_time)
            finally:
                # Close all connections
                for conn in connections.values():
                    conn.close()
            
            total_time = time.time() - start_time
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Average query time: {statistics.mean(query_times):.3f}s")
            print(f"  Queries per second: {num_queries / total_time:.1f}")
            
            return query_times, total_time
            
        finally:
            # Clean up sync table
            self.cleanup_test_data(table_name)
    
    async def benchmark_async(self, num_queries: int, max_concurrent: int) -> Tuple[List[float], float]:
        """Benchmark async connector with setup/teardown per benchmark."""
        # Create table for async benchmark 
        table_name = self.setup_test_data("_ASYNC")
        
        try:
            print(f"⚡ Running {num_queries} async queries with {max_concurrent} concurrent tasks...")
            
            # Create connections for async workers (one per concurrent task)
            connections = []
            
            try:
                # Create limited number of connections for concurrent tasks
                for i in range(max_concurrent):
                    conn = await snowflake.connector.aio.connect(**self.conn_params)
                    cursor = conn.cursor()
                    await cursor.execute(f"USE DATABASE {self.conn_params['database']}")
                    await cursor.execute(f"USE SCHEMA {self.conn_params['schema']}")
                    connections.append(conn)
                
                start_time = time.time()
                
                # Create semaphore to limit concurrency
                semaphore = asyncio.Semaphore(max_concurrent)
                connection_index = 0
                
                async def limited_query(query_id: int):
                    nonlocal connection_index
                    async with semaphore:
                        # Use round-robin to assign connections
                        conn = connections[connection_index % len(connections)]
                        connection_index += 1
                        return await self.async_query_worker(conn, table_name, query_id)
                
                # Execute all queries concurrently
                tasks = [limited_query(i) for i in range(num_queries)]
                results = await asyncio.gather(*tasks)
                
                query_times = [result[1] for result in results]
                total_time = time.time() - start_time
                
                print(f"  Total time: {total_time:.2f}s")
                print(f"  Average query time: {statistics.mean(query_times):.3f}s")
                print(f"  Queries per second: {num_queries / total_time:.1f}")
                
                return query_times, total_time
                
            finally:
                # Close all async connections
                for conn in connections:
                    await conn.close()
                    
        finally:
            # Clean up async table
            self.cleanup_test_data(table_name)
    
    def print_comparison(self, sync_times: List[float], async_times: List[float], sync_total: float, async_total: float):
        """Print detailed performance comparison."""
        print("\n" + "="*60)
        print("📊 PERFORMANCE COMPARISON")
        print("="*60)
        
        sync_stats = {
            'mean': statistics.mean(sync_times),
            'median': statistics.median(sync_times),
            'min': min(sync_times),
            'max': max(sync_times),
            'stdev': statistics.stdev(sync_times) if len(sync_times) > 1 else 0
        }
        
        async_stats = {
            'mean': statistics.mean(async_times),
            'median': statistics.median(async_times),
            'min': min(async_times),
            'max': max(async_times),
            'stdev': statistics.stdev(async_times) if len(async_times) > 1 else 0
        }
        
        print(f"{'Metric':<15} {'Sync':<12} {'Async':<12} {'Improvement':<12}")
        print("-" * 55)
        
        for metric in ['mean', 'median', 'min', 'max', 'stdev']:
            sync_val = sync_stats[metric]
            async_val = async_stats[metric]
            improvement = ((sync_val - async_val) / sync_val * 100) if sync_val > 0 else 0
            
            print(f"{metric.capitalize():<15} {sync_val:<12.3f} {async_val:<12.3f} {improvement:>+8.1f}%")
        
        print("\n📈 PERFORMANCE ANALYSIS:")
        
        # Throughput analysis
        sync_throughput = len(sync_times) / sync_total
        async_throughput = len(async_times) / async_total
        throughput_improvement = ((async_throughput - sync_throughput) / sync_throughput * 100)
        
        print(f"🚀 THROUGHPUT (System Performance):")
        print(f"  • Sync: {sync_throughput:.1f} queries/second")
        print(f"  • Async: {async_throughput:.1f} queries/second")
        print(f"  • Throughput improvement: {throughput_improvement:+.1f}%")
        
        # Query latency analysis  
        sync_latency = statistics.mean(sync_times)
        async_latency = statistics.mean(async_times)
        latency_change = ((async_latency - sync_latency) / sync_latency * 100)
        
        print(f"\n⏱️  QUERY LATENCY (Individual Performance):")
        print(f"  • Sync average: {sync_latency:.3f}s per query")
        print(f"  • Async average: {async_latency:.3f}s per query") 
        print(f"  • Latency change: {latency_change:+.1f}%")
        
        # Overall assessment
        print(f"\n📊 OVERALL ASSESSMENT:")
        overall_improvement = ((sync_total - async_total) / sync_total * 100)
        print(f"  • Total time - Sync: {sync_total:.2f}s, Async: {async_total:.2f}s")
        
        if overall_improvement > 0:
            print(f"  • ✅ Async is {overall_improvement:.1f}% faster overall! ⚡")
        else:
            print(f"  • ⚠️  Sync is {abs(overall_improvement):.1f}% faster overall")
            
        # Performance warnings and insights
        print(f"\n🔍 INSIGHTS:")
        if latency_change > 50:
            print(f"  • ⚠️  High latency increase ({latency_change:.1f}%) - possible over-parallelization")
        elif latency_change > 20:
            print(f"  • ⚠️  Moderate latency increase ({latency_change:.1f}%) - monitor concurrency levels")
        elif latency_change > 0:
            print(f"  • ℹ️  Small latency overhead ({latency_change:.1f}%) - normal for async")
        else:
            print(f"  • ✅ Async latency improvement ({latency_change:.1f}%) - excellent!")
            
        if throughput_improvement > 100:
            print(f"  • 🚀 Excellent throughput scaling ({throughput_improvement:.1f}%)")
        elif throughput_improvement > 50:
            print(f"  • ✅ Good throughput improvement ({throughput_improvement:.1f}%)")
        elif throughput_improvement > 0:
            print(f"  • ℹ️  Modest throughput gain ({throughput_improvement:.1f}%)")
        else:
            print(f"  • ⚠️  Async throughput regression ({throughput_improvement:.1f}%) - investigate async code")

    async def run_benchmark(
        self, 
        num_queries: int = 100,
        max_workers: int = 10
    ):
        """Run the complete benchmark with separate tables for sync and async."""
        print("🚀 Starting Snowflake Sync vs Async Benchmark")
        print(f"   Queries: {num_queries}")
        print(f"   Max workers/concurrent: {max_workers}")
        print(f"   Base table: {self.table_name} ({self.row_count:,} rows)")
        print("   Each benchmark creates its own table for optimal settling")
        print()
        
        # Run sync benchmark (creates, uses, and cleans up its own table)
        sync_times, sync_total = self.benchmark_sync(num_queries, max_workers)
        print()
        
        # Run async benchmark (creates, uses, and cleans up its own table)
        async_times, async_total = await self.benchmark_async(num_queries, max_workers)
        print()
        
        # Compare results
        self.print_comparison(sync_times, async_times, sync_total, async_total)


async def main():
    """Main benchmark entry point."""
    # Parse command line arguments or use defaults
    import argparse
    
    parser = argparse.ArgumentParser(description="Benchmark Snowflake sync vs async connectors")
    parser.add_argument("--queries", type=int, default=100, help="Number of queries to run (default: 100)")
    parser.add_argument("--workers", type=int, default=10, help="Max workers/concurrent tasks (default: 10)")
    parser.add_argument("--env-file", default=".env", help="Environment file path (default: .env)")
    
    args = parser.parse_args()
    
    try:
        benchmark = SnowflakeBenchmark(args.env_file)
        await benchmark.run_benchmark(
            num_queries=args.queries,
            max_workers=args.workers
        )
    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())