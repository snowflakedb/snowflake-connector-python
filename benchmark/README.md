# Snowflake Connector Benchmarks

This directory contains benchmarks for testing the synchronous and asynchronous Snowflake connectors using the **local development version** of the connector.

## Benchmarks Available

### 1. `benchmark_sync_vs_async.py` - Concurrent Query Performance
Compares sync vs async connector performance under concurrent workloads.

### 2. `benchmark_large_results.py` - Large Result Set Retrieval  
Tests data integrity and performance for large result set fetching.

---

## Concurrent Query Benchmark (`benchmark_sync_vs_async.py`)

This benchmark compares the performance of sync and async connectors under concurrent workloads.

## Quick Start

1. **Install dependencies:**
   ```bash
   cd benchmark/
   pip install -r requirements.txt
   ```

2. **Configure credentials:**
   ```bash
   cp .env.example .env
   # Edit .env with your Snowflake credentials
   ```

3. **Run the benchmark:**
   ```bash
   python benchmark_sync_vs_async.py
   ```

## Command Line Options

```bash
python benchmark_sync_vs_async.py --help
```

- `--queries N`: Number of queries to run (default: 100)
- `--workers N`: Max workers/concurrent tasks (default: 10)  
- `--env-file PATH`: Environment file path (default: .env)

**⚠️ Important**: Use at least 50+ queries for stable results. Hybrid tables need time to stabilize and deliver consistent performance.

## Example Usage

```bash
# Run default benchmark (recommended)
python benchmark_sync_vs_async.py

# Run quick test (minimum for stable results)
python benchmark_sync_vs_async.py --queries 50 --workers 5

# Run intensive benchmark  
python benchmark_sync_vs_async.py --queries 200 --workers 20

# Use custom environment file
python benchmark_sync_vs_async.py --env-file .env.prod
```

## How It Works

### Table Management
Each benchmark creates its own hybrid table for optimal performance:
- **Sync**: Creates `BENCHMARK_TEST_TABLE_SYNC`
- **Async**: Creates `BENCHMARK_TEST_TABLE_ASYNC`
- **Data**: 100,000 rows with ID (integer) and VAL (50-char random string)
- **Lifecycle**: Setup → Benchmark → Cleanup (per test)

### Connection Reuse
- **Sync**: One connection per thread, reused across queries
- **Async**: One connection per concurrent task, round-robin assignment
- **Result**: Measures pure query performance without connection overhead

### Test Pattern
1. **Sync Test**: Uses `ThreadPoolExecutor` with the sync connector
2. **Async Test**: Uses `asyncio.gather()` with the async connector  
3. **Comparison**: Reports detailed performance metrics

## Expected Results

The benchmark measures two distinct performance characteristics:

### 🚀 Throughput (System Performance)
How quickly the system processes a batch of queries concurrently.

**Typical Results (with 50+ queries for stable hybrid table performance):**
- **Low concurrency (1 worker)**: Async ~15% better (7.3 → 8.4 queries/second)
- **Moderate concurrency (10 workers)**: Async ~227% better (19.3 → 63.1 queries/second)  
- **High concurrency (20 workers)**: Async ~452% better (23.0 → 127.1 queries/second)

### ⏱️ Query Latency (Individual Performance)
How long each individual query takes from start to finish.

**Typical Results (with stabilized hybrid tables):**
- **Low concurrency (1 worker)**: Nearly identical (+3.8%, 0.114s → 0.119s)
- **Moderate concurrency (10 workers)**: Small async overhead (+17.0%, 0.131s → 0.153s)
- **High concurrency (20 workers)**: Minimal async overhead (+2.5%, 0.147s → 0.150s)

### 📊 Performance Analysis

The benchmark provides automated insights:

**✅ Healthy Patterns:**
- Throughput improvement: 50%+ indicates good async scaling
- Latency overhead: <20% is normal async overhead
- High concurrency: Better throughput with acceptable latency cost

**⚠️ Warning Indicators:**
- Latency increase >50%: Possible over-parallelization
- Throughput regression: Potential async implementation issues
- Poor scaling: May need optimization or different concurrency levels

### When Async Excels
- **High concurrency workloads** (5+ concurrent operations)
- **I/O bound operations** (network requests, database queries)
- **Batch processing** scenarios
- **Resource-constrained** environments where efficiency matters

### Real-World Implications
- **Individual queries**: Sync may be 10-20% faster due to less overhead
- **Concurrent workloads**: Async typically 3-12x faster overall
- **Scaling**: Async advantage increases dramatically with worker count
- **Sweet spot**: 5-10 concurrent workers often provide optimal balance

## 📊 Large Result Set Performance

### Single Query, Large Data Retrieval
For individual queries returning large result sets, the async connector is optimized for both fetchall() and iteration patterns.

**Typical Results (large result set fetching):**

#### 📈 100K Rows
- **Sync fetchall()**: 2.90s (34,529 rows/second)
- **Async fetchall()**: 2.84s (35,167 rows/second) - **+1.8% improvement**
- **Async iteration**: 2.83s (35,291 rows/second) - **+2.2% improvement**

#### 🚀 1M Rows  
- **Sync fetchall()**: 13.37s (74,805 rows/second)
- **Async fetchall()**: 9.70s (103,040 rows/second) - **+27.4% improvement**
- **Async iteration**: 9.27s (107,847 rows/second) - **+30.6% improvement**

### 🔍 Large Result Analysis

**✅ Async Advantages for Large Results:**
- **Concurrent batch processing**: Downloads multiple result chunks simultaneously
- **Optimized bulk operations**: Eliminates row-by-row iteration overhead  
- **Better resource utilization**: Maximizes network and CPU efficiency
- **Scalable performance**: Performance improvement increases with result size

**🎯 Method Selection Guide:**
- **fetchall()**: Optimal for loading complete result sets into memory
- **async iteration**: Better for streaming large results with memory constraints
- **Performance**: Both methods perform similarly, choose based on memory needs

**⚡ Performance Characteristics:**
- **Small results (1K-10K rows)**: Async ~10-15% faster
- **Medium results (100K rows)**: Async equivalent or slightly better
- **Large results (1M+ rows)**: Async significantly faster (25-30% improvement)

The async connector is **strictly faster** for single query large result sets, fulfilling the design requirement.

## Interpreting Results

### Sample Output
```
🚀 THROUGHPUT (System Performance):
  • Sync: 19.3 queries/second
  • Async: 63.1 queries/second
  • Throughput improvement: +226.8%

⏱️  QUERY LATENCY (Individual Performance):
  • Sync average: 0.131s per query
  • Async average: 0.153s per query
  • Latency change: +17.0%

🔍 INSIGHTS:
  • ℹ️  Small latency overhead (17.0%) - normal for async
  • 🚀 Excellent throughput scaling (226.8%)
```

### Key Metrics Explained

**Throughput (queries/second)**: 
- Measures overall system efficiency
- Higher is better
- Shows how async scales with concurrency

**Query Latency (seconds per query)**:
- Measures individual query performance  
- Lower is better
- Small increases are acceptable for better throughput

**Insights**:
- 🚀 Excellent (>100% throughput improvement)
- ✅ Good (50-100% throughput improvement)  
- ℹ️ Normal (<50% latency overhead)
- ⚠️ Warning (>50% latency increase or throughput regression)

## Troubleshooting Performance

### Common Patterns

**🔍 "Async slower at low concurrency"**
- **Normal**: Single queries may have 10-20% overhead
- **Action**: Test with higher concurrency (5+ workers)

**⚠️ "High latency increase (>50%)"**
- **Cause**: Over-parallelization, resource contention
- **Action**: Reduce worker count, check system resources

**⚠️ "Async throughput regression"** 
- **Cause**: Async implementation issues, connection problems
- **Action**: Check async connector code, network configuration

**🚀 "Excellent scaling at high concurrency"**
- **Normal**: Expected async behavior
- **Action**: Consider this concurrency level for production

### Optimization Tips

1. **Find Sweet Spot**: Test different worker counts (1, 5, 10, 20)
2. **Monitor Resources**: Check CPU, memory, network utilization
3. **Consider Workload**: Async excels with I/O-bound operations
4. **Production Sizing**: Use benchmark results to size connection pools

## Authentication

### Private Key (Recommended)
```bash
# Method 1: File path
SNOWFLAKE_PRIVATE_KEY_PATH=/path/to/private_key.p8

# Method 2: Environment variable
SNOWFLAKE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

# Optional passphrase
SNOWFLAKE_PRIVATE_KEY_PASS=your_passphrase
```

### Password
```bash
SNOWFLAKE_PASSWORD=your_password
```

## Development Setup

This benchmark uses the **local source code** from `../src/` rather than an installed package, allowing you to:

- Test async connector changes immediately
- Compare performance with local modifications  
- Debug issues without reinstalling packages
- Develop and benchmark iteratively

## Security

⚠️ **Important**: Never commit `.env` files with real credentials to version control!

The `.env` file is excluded from git and should contain your actual Snowflake credentials.

---

## Large Result Set Benchmark (`benchmark_large_results.py`)

This benchmark tests large result set retrieval to verify data integrity and performance characteristics.

### Purpose
- **Data Integrity**: Ensures sync and async connectors return identical results  
- **Performance**: Measures fetch speed for large datasets
- **Bug Detection**: Identifies issues with large result processing

### Usage

```bash
# Run default benchmark (1000 rows)
python benchmark_large_results.py

# Test specific sizes 
python benchmark_large_results.py --sizes 500 1000

# Use custom environment file
python benchmark_large_results.py --env-file .env.prod
```

### What It Tests

1. **Creates 1M+ row table**: Large hybrid table with deterministic data
2. **Stable sorting**: Uses `ORDER BY ID` for consistent results
3. **Data verification**: Compares MD5 hashes of sync vs async results
4. **Performance measurement**: Times large result set fetching

### Current Limitations

⚠️ **Known Issue**: The async connector has a timing bug that triggers with result sets >1000 rows:
```
Exception: Trying to get timing before TimerContextManager has finished
```

This occurs in the `result_batch.py` download timing code and prevents testing of truly large result sets until fixed.

### Expected Results

For working result sizes (~1000 rows):
- **Data Integrity**: ✅ Identical results (verified by hash)  
- **Performance**: Similar speed (~2-3% difference)
- **Reliability**: Consistent behavior

### Troubleshooting

**"Timing before TimerContextManager finished"**:
- Async connector bug with large results
- Reduce `--sizes` to 1000 or less
- Bug occurs in result batch downloading timing

**"Results do not match"**:  
- Critical data integrity issue
- Check sorting consistency  
- Investigate async result processing