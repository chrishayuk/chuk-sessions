#!/usr/bin/env python3
"""
CHUK Sessions Performance Testing Script

This script benchmarks the performance of different session providers
to provide accurate performance metrics for documentation.
"""

import asyncio
import os
import time
import statistics
import json
import platform
import psutil
from typing import List, Dict, Any
from contextlib import asynccontextmanager

from chuk_sessions.provider_factory import factory_for_env


class PerformanceTester:
    """Performance testing utility for session providers."""
    
    def __init__(self):
        self.results = {}
        self.system_info = self._get_system_info()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for benchmark context."""
        return {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "cpu_freq_ghz": round(psutil.cpu_freq().max / 1000, 1) if psutil.cpu_freq() else "Unknown"
        }
    
    async def benchmark_provider(self, provider_name: str, operations: int = 1000) -> Dict[str, Any]:
        """Benchmark a specific provider."""
        print(f"\n🔍 Benchmarking {provider_name.upper()} provider...")
        print(f"   Operations: {operations:,}")
        
        # Configure the provider
        os.environ['SESSION_PROVIDER'] = provider_name
        if provider_name == 'redis':
            os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/15'  # Use DB 15 for testing
        
        session_factory = factory_for_env()
        
        # Test data
        test_key = "perf_test_key"
        test_value = "x" * 100  # 100 byte value
        large_value = "x" * 10000  # 10KB value
        json_value = json.dumps({
            "user_id": "12345",
            "username": "testuser",
            "permissions": ["read", "write", "admin"],
            "metadata": {"last_login": "2024-01-01", "session_count": 42}
        })
        
        results = {}
        
        try:
            async with session_factory() as session:
                # Warm up
                for i in range(10):
                    await session.setex(f"warmup_{i}", 60, "warmup")
                    await session.get(f"warmup_{i}")
                
                # Test SET operations
                print("   Testing SET operations...")
                set_times = []
                start_time = time.perf_counter()
                
                for i in range(operations):
                    op_start = time.perf_counter()
                    await session.setex(f"{test_key}_{i}", 60, test_value)
                    op_end = time.perf_counter()
                    set_times.append((op_end - op_start) * 1000)  # Convert to milliseconds
                
                total_set_time = time.perf_counter() - start_time
                
                # Test GET operations
                print("   Testing GET operations...")
                get_times = []
                start_time = time.perf_counter()
                
                for i in range(operations):
                    op_start = time.perf_counter()
                    result = await session.get(f"{test_key}_{i}")
                    op_end = time.perf_counter()
                    get_times.append((op_end - op_start) * 1000)
                    assert result == test_value, "Data integrity check failed"
                
                total_get_time = time.perf_counter() - start_time
                
                # Test DELETE operations
                print("   Testing DELETE operations...")
                delete_times = []
                start_time = time.perf_counter()
                
                for i in range(operations):
                    op_start = time.perf_counter()
                    await session.delete(f"{test_key}_{i}")
                    op_end = time.perf_counter()
                    delete_times.append((op_end - op_start) * 1000)
                
                total_delete_time = time.perf_counter() - start_time
                
                # Test large value operations
                print("   Testing large value operations...")
                large_set_start = time.perf_counter()
                await session.setex("large_test", 60, large_value)
                large_set_time = (time.perf_counter() - large_set_start) * 1000
                
                large_get_start = time.perf_counter()
                large_result = await session.get("large_test")
                large_get_time = (time.perf_counter() - large_get_start) * 1000
                
                assert large_result == large_value, "Large data integrity check failed"
                await session.delete("large_test")
                
                # Test JSON operations
                print("   Testing JSON operations...")
                json_set_start = time.perf_counter()
                await session.setex("json_test", 60, json_value)
                json_set_time = (time.perf_counter() - json_set_start) * 1000
                
                json_get_start = time.perf_counter()
                json_result = await session.get("json_test")
                json_get_time = (time.perf_counter() - json_get_start) * 1000
                
                assert json_result == json_value, "JSON data integrity check failed"
                await session.delete("json_test")
                
                # Compile results
                results = {
                    "provider": provider_name,
                    "operations": operations,
                    "set": {
                        "total_time_sec": total_set_time,
                        "ops_per_sec": operations / total_set_time,
                        "avg_latency_ms": statistics.mean(set_times),
                        "median_latency_ms": statistics.median(set_times),
                        "p95_latency_ms": self._percentile(set_times, 0.95),
                        "min_latency_ms": min(set_times),
                        "max_latency_ms": max(set_times)
                    },
                    "get": {
                        "total_time_sec": total_get_time,
                        "ops_per_sec": operations / total_get_time,
                        "avg_latency_ms": statistics.mean(get_times),
                        "median_latency_ms": statistics.median(get_times),
                        "p95_latency_ms": self._percentile(get_times, 0.95),
                        "min_latency_ms": min(get_times),
                        "max_latency_ms": max(get_times)
                    },
                    "delete": {
                        "total_time_sec": total_delete_time,
                        "ops_per_sec": operations / total_delete_time,
                        "avg_latency_ms": statistics.mean(delete_times),
                        "median_latency_ms": statistics.median(delete_times),
                        "p95_latency_ms": self._percentile(delete_times, 0.95),
                        "min_latency_ms": min(delete_times),
                        "max_latency_ms": max(delete_times)
                    },
                    "large_value": {
                        "set_latency_ms": large_set_time,
                        "get_latency_ms": large_get_time,
                        "size_kb": len(large_value) / 1024
                    },
                    "json_value": {
                        "set_latency_ms": json_set_time,
                        "get_latency_ms": json_get_time,
                        "size_bytes": len(json_value)
                    }
                }
                
                print(f"   ✅ Completed {operations:,} operations")
                
        except Exception as e:
            print(f"   ❌ Error during {provider_name} benchmark: {e}")
            results = {"error": str(e)}
        
        return results
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile of a list."""
        sorted_data = sorted(data)
        index = int(percentile * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    async def test_memory_usage(self, provider_name: str) -> Dict[str, Any]:
        """Test memory usage patterns."""
        print(f"\n💾 Testing memory usage for {provider_name.upper()}...")
        
        os.environ['SESSION_PROVIDER'] = provider_name
        if provider_name == 'redis':
            os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/15'
        
        session_factory = factory_for_env()
        
        # Get baseline memory
        process = psutil.Process()
        baseline_memory = process.memory_info().rss
        
        async with session_factory() as session:
            # Store increasing amounts of data
            memory_measurements = []
            
            for batch in [100, 500, 1000, 5000, 10000]:
                # Store data
                for i in range(batch):
                    await session.setex(f"mem_test_{i}", 300, f"data_{i}" * 10)  # ~70 bytes per item
                
                # Measure memory
                current_memory = process.memory_info().rss
                memory_delta = current_memory - baseline_memory
                
                memory_measurements.append({
                    "items": batch,
                    "memory_mb": memory_delta / (1024 * 1024),
                    "bytes_per_item": memory_delta / batch if batch > 0 else 0
                })
                
                # Clean up
                for i in range(batch):
                    await session.delete(f"mem_test_{i}")
        
        return {
            "provider": provider_name,
            "measurements": memory_measurements
        }
    
    async def test_concurrent_access(self, provider_name: str, concurrent_sessions: int = 10) -> Dict[str, Any]:
        """Test concurrent access performance."""
        print(f"\n🚀 Testing concurrent access for {provider_name.upper()} ({concurrent_sessions} sessions)...")
        
        os.environ['SESSION_PROVIDER'] = provider_name
        if provider_name == 'redis':
            os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/15'
        
        session_factory = factory_for_env()
        
        async def worker_task(worker_id: int, operations: int):
            """Single worker performing operations."""
            times = []
            async with session_factory() as session:
                for i in range(operations):
                    start = time.perf_counter()
                    await session.setex(f"worker_{worker_id}_item_{i}", 60, f"data_{i}")
                    result = await session.get(f"worker_{worker_id}_item_{i}")
                    await session.delete(f"worker_{worker_id}_item_{i}")
                    end = time.perf_counter()
                    times.append((end - start) * 1000)
            return times
        
        # Run concurrent workers
        operations_per_worker = 100
        start_time = time.perf_counter()
        
        tasks = [worker_task(i, operations_per_worker) for i in range(concurrent_sessions)]
        results = await asyncio.gather(*tasks)
        
        total_time = time.perf_counter() - start_time
        
        # Aggregate results
        all_times = [time for worker_times in results for time in worker_times]
        total_operations = concurrent_sessions * operations_per_worker
        
        return {
            "provider": provider_name,
            "concurrent_sessions": concurrent_sessions,
            "operations_per_session": operations_per_worker,
            "total_operations": total_operations,
            "total_time_sec": total_time,
            "overall_ops_per_sec": total_operations / total_time,
            "avg_latency_ms": statistics.mean(all_times),
            "p95_latency_ms": self._percentile(all_times, 0.95)
        }
    
    def print_results(self, results: Dict[str, Any]):
        """Print formatted benchmark results."""
        print("\n" + "=" * 70)
        print("📊 PERFORMANCE BENCHMARK RESULTS")
        print("=" * 70)
        
        print(f"\n🖥️  System Information:")
        for key, value in self.system_info.items():
            print(f"   {key}: {value}")
        
        for provider, data in results.items():
            if "error" in data:
                print(f"\n❌ {provider.upper()}: {data['error']}")
                continue
                
            print(f"\n🚀 {provider.upper()} Provider Results:")
            print(f"   Operations: {data['operations']:,}")
            
            for op_type in ['set', 'get', 'delete']:
                if op_type in data:
                    op_data = data[op_type]
                    print(f"\n   {op_type.upper()} Operations:")
                    print(f"      Throughput: {op_data['ops_per_sec']:,.0f} ops/sec")
                    print(f"      Avg Latency: {op_data['avg_latency_ms']:.3f} ms")
                    print(f"      Median Latency: {op_data['median_latency_ms']:.3f} ms")
                    print(f"      P95 Latency: {op_data['p95_latency_ms']:.3f} ms")
            
            if 'large_value' in data:
                large = data['large_value']
                print(f"\n   Large Value ({large['size_kb']:.1f} KB):")
                print(f"      SET: {large['set_latency_ms']:.3f} ms")
                print(f"      GET: {large['get_latency_ms']:.3f} ms")
            
            if 'json_value' in data:
                json_data = data['json_value']
                print(f"\n   JSON Value ({json_data['size_bytes']} bytes):")
                print(f"      SET: {json_data['set_latency_ms']:.3f} ms")
                print(f"      GET: {json_data['get_latency_ms']:.3f} ms")
    
    def print_memory_results(self, results: List[Dict[str, Any]]):
        """Print memory usage results."""
        print("\n" + "=" * 70)
        print("💾 MEMORY USAGE RESULTS")
        print("=" * 70)
        
        for result in results:
            if "error" in result:
                continue
                
            print(f"\n{result['provider'].upper()} Provider:")
            for measurement in result['measurements']:
                print(f"   {measurement['items']:,} items: "
                      f"{measurement['memory_mb']:.1f} MB "
                      f"({measurement['bytes_per_item']:.0f} bytes/item)")
    
    def print_concurrent_results(self, results: List[Dict[str, Any]]):
        """Print concurrent access results."""
        print("\n" + "=" * 70)
        print("🚀 CONCURRENT ACCESS RESULTS")
        print("=" * 70)
        
        for result in results:
            if "error" in result:
                continue
                
            print(f"\n{result['provider'].upper()} Provider:")
            print(f"   Concurrent Sessions: {result['concurrent_sessions']}")
            print(f"   Total Operations: {result['total_operations']:,}")
            print(f"   Overall Throughput: {result['overall_ops_per_sec']:,.0f} ops/sec")
            print(f"   Average Latency: {result['avg_latency_ms']:.3f} ms")
            print(f"   P95 Latency: {result['p95_latency_ms']:.3f} ms")


async def main():
    """Run comprehensive performance tests."""
    tester = PerformanceTester()
    
    print("🎯 CHUK Sessions Performance Testing")
    print("🔧 This may take several minutes to complete...")
    
    providers_to_test = ['memory']
    
    # Check if Redis is available
    try:
        import redis.asyncio as aioredis
        # Try to connect to Redis
        redis_client = aioredis.from_url('redis://localhost:6379/15')
        await redis_client.ping()
        await redis_client.close()
        providers_to_test.append('redis')
        print("✅ Redis detected - will test both providers")
    except Exception:
        print("⚠️  Redis not available - testing memory provider only")
    
    # Run basic performance tests
    basic_results = {}
    for provider in providers_to_test:
        result = await tester.benchmark_provider(provider, operations=1000)
        basic_results[provider] = result
    
    tester.print_results(basic_results)
    
    # Run memory usage tests
    print("\n🔍 Running memory usage tests...")
    memory_results = []
    for provider in providers_to_test:
        result = await tester.test_memory_usage(provider)
        memory_results.append(result)
    
    tester.print_memory_results(memory_results)
    
    # Run concurrent access tests
    print("\n🔍 Running concurrent access tests...")
    concurrent_results = []
    for provider in providers_to_test:
        result = await tester.test_concurrent_access(provider, concurrent_sessions=5)
        concurrent_results.append(result)
    
    tester.print_concurrent_results(concurrent_results)
    
    # Generate summary table for README
    print("\n" + "=" * 70)
    print("📋 README TABLE FORMAT")
    print("=" * 70)
    print("\n| Provider | Operation | Avg Latency | Throughput |")
    print("|----------|-----------|-------------|------------|")
    
    for provider, data in basic_results.items():
        if "error" not in data:
            for op in ['get', 'set']:
                if op in data:
                    latency = data[op]['avg_latency_ms']
                    throughput = data[op]['ops_per_sec']
                    print(f"| {provider.title()} | {op.upper()} | {latency:.2f}ms | {throughput:,.0f} ops/sec |")


if __name__ == "__main__":
    asyncio.run(main())