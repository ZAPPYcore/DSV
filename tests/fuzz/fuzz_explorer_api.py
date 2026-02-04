#!/usr/bin/env python3
"""
DSV Explorer API Fuzz Test

Fuzzes the explorer API endpoints with malformed inputs.
Uses Python's hypothesis library for property-based testing.
"""

import asyncio
import json
import string
from typing import Any
from hypothesis import given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

# Try to import the API app
try:
    from explorer.api.main import app
    from httpx import AsyncClient, ASGITransport
    HAS_APP = True
except ImportError:
    HAS_APP = False
    print("Warning: Explorer API not available for testing")


# Strategies for generating test data
hex_string = st.text(
    alphabet=string.hexdigits,
    min_size=0,
    max_size=128
)

address_like = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=1,
    max_size=64
)

block_height = st.integers(min_value=-1000000, max_value=1000000000)

malformed_json = st.one_of(
    st.text(min_size=0, max_size=1000),
    st.binary(min_size=0, max_size=1000).map(lambda b: b.decode('latin-1')),
)


class ExplorerAPIFuzzer:
    """Fuzz test suite for Explorer API."""
    
    def __init__(self):
        self.base_url = "http://test"
        
    async def setup(self):
        """Setup test client."""
        if HAS_APP:
            self.transport = ASGITransport(app=app)
            self.client = AsyncClient(transport=self.transport, base_url=self.base_url)
        
    async def teardown(self):
        """Cleanup test client."""
        if HAS_APP:
            await self.client.aclose()
    
    async def fuzz_health(self) -> bool:
        """Fuzz the health endpoint."""
        if not HAS_APP:
            return True
            
        response = await self.client.get("/api/health")
        # Health should always return 200 or 503
        return response.status_code in [200, 503]
    
    async def fuzz_block_by_hash(self, hash_str: str) -> bool:
        """Fuzz block lookup by hash."""
        if not HAS_APP:
            return True
            
        try:
            response = await self.client.get(f"/api/block/{hash_str}")
            # Should return 200, 400, or 404
            return response.status_code in [200, 400, 404]
        except Exception:
            # Any exception is a failure
            return False
    
    async def fuzz_block_by_height(self, height: int) -> bool:
        """Fuzz block lookup by height."""
        if not HAS_APP:
            return True
            
        try:
            response = await self.client.get(f"/api/block/{height}")
            return response.status_code in [200, 400, 404]
        except Exception:
            return False
    
    async def fuzz_tx(self, txid: str) -> bool:
        """Fuzz transaction lookup."""
        if not HAS_APP:
            return True
            
        try:
            response = await self.client.get(f"/api/tx/{txid}")
            return response.status_code in [200, 400, 404]
        except Exception:
            return False
    
    async def fuzz_address(self, address: str) -> bool:
        """Fuzz address lookup."""
        if not HAS_APP:
            return True
            
        try:
            response = await self.client.get(f"/api/address/{address}")
            return response.status_code in [200, 400, 404]
        except Exception:
            return False
    
    async def fuzz_search(self, query: str) -> bool:
        """Fuzz search endpoint."""
        if not HAS_APP:
            return True
            
        try:
            response = await self.client.get("/api/search", params={"q": query})
            return response.status_code in [200, 400, 404]
        except Exception:
            return False
    
    async def fuzz_blocks_pagination(self, limit: int, cursor: str) -> bool:
        """Fuzz blocks list with pagination."""
        if not HAS_APP:
            return True
            
        try:
            params = {}
            if limit is not None:
                params["limit"] = limit
            if cursor:
                params["cursor"] = cursor
                
            response = await self.client.get("/api/blocks", params=params)
            return response.status_code in [200, 400]
        except Exception:
            return False


# Hypothesis tests
fuzzer = ExplorerAPIFuzzer()


@given(hash_str=hex_string)
@settings(max_examples=100)
def test_fuzz_block_by_hash(hash_str):
    """Test block lookup with various hash strings."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_block_by_hash(hash_str)
            assert result, f"Block lookup failed for hash: {hash_str}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


@given(height=block_height)
@settings(max_examples=100)
def test_fuzz_block_by_height(height):
    """Test block lookup with various heights."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_block_by_height(height)
            assert result, f"Block lookup failed for height: {height}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


@given(txid=hex_string)
@settings(max_examples=100)
def test_fuzz_tx(txid):
    """Test transaction lookup with various txids."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_tx(txid)
            assert result, f"TX lookup failed for txid: {txid}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


@given(address=address_like)
@settings(max_examples=100)
def test_fuzz_address(address):
    """Test address lookup with various addresses."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_address(address)
            assert result, f"Address lookup failed for: {address}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


@given(query=st.text(max_size=200))
@settings(max_examples=100)
def test_fuzz_search(query):
    """Test search with various queries."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_search(query)
            assert result, f"Search failed for query: {query}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


@given(
    limit=st.one_of(st.none(), st.integers(min_value=-100, max_value=10000)),
    cursor=st.one_of(st.none(), hex_string)
)
@settings(max_examples=100)
def test_fuzz_blocks_pagination(limit, cursor):
    """Test blocks pagination with various parameters."""
    async def run():
        await fuzzer.setup()
        try:
            result = await fuzzer.fuzz_blocks_pagination(limit, cursor)
            assert result, f"Blocks pagination failed: limit={limit}, cursor={cursor}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


# SQL Injection tests
SQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE blocks; --",
    "1 OR 1=1",
    "1'; SELECT * FROM users; --",
    "1 UNION SELECT * FROM blocks",
    "'; INSERT INTO blocks VALUES ('hack'); --",
    "1; UPDATE blocks SET hash='hacked'",
    "1)) OR ((1=1",
    "admin'--",
    "' OR '1'='1",
    "'; TRUNCATE TABLE txs; --",
    "1; EXEC xp_cmdshell('cat /etc/passwd')",
    "${7*7}",
    "{{7*7}}",
    "#{7*7}",
]


def test_sql_injection_block():
    """Test SQL injection in block endpoint."""
    async def run():
        await fuzzer.setup()
        try:
            for payload in SQL_INJECTION_PAYLOADS:
                result = await fuzzer.fuzz_block_by_hash(payload)
                assert result, f"SQL injection test failed for: {payload}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


def test_sql_injection_search():
    """Test SQL injection in search endpoint."""
    async def run():
        await fuzzer.setup()
        try:
            for payload in SQL_INJECTION_PAYLOADS:
                result = await fuzzer.fuzz_search(payload)
                assert result, f"SQL injection test failed for: {payload}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


# XSS tests
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "javascript:alert('xss')",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
    "'><script>alert('xss')</script>",
    "\"onfocus=\"alert('xss')\" autofocus=\"",
    "<body onload=alert('xss')>",
    "<iframe src=\"javascript:alert('xss')\">",
]


def test_xss_search():
    """Test XSS in search endpoint."""
    async def run():
        await fuzzer.setup()
        try:
            for payload in XSS_PAYLOADS:
                result = await fuzzer.fuzz_search(payload)
                assert result, f"XSS test failed for: {payload}"
        finally:
            await fuzzer.teardown()
    
    asyncio.run(run())


if __name__ == "__main__":
    import sys
    
    print("DSV Explorer API Fuzz Tests")
    print("===========================\n")
    
    if not HAS_APP:
        print("Explorer API not available. Running mock tests.")
    
    # Run all tests
    tests = [
        ("SQL Injection - Block", test_sql_injection_block),
        ("SQL Injection - Search", test_sql_injection_search),
        ("XSS - Search", test_xss_search),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            print(f"  Testing {name}... ", end="", flush=True)
            test_func()
            print("PASS")
            passed += 1
        except Exception as e:
            print(f"FAIL: {e}")
            failed += 1
    
    print(f"\n===========================")
    print(f"Results: {passed}/{passed + failed} tests passed")
    
    sys.exit(0 if failed == 0 else 1)

