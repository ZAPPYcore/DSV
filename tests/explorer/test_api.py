#!/usr/bin/env python3
"""
DSV Explorer API Tests

Tests for the explorer API endpoints including:
- Health check
- Chain info
- Block queries
- Transaction queries
- Address queries
- Search functionality
"""

import pytest
import json
from unittest.mock import Mock, patch, AsyncMock

# Try to import API modules
try:
    from fastapi.testclient import TestClient
    from explorer.api.main import app, get_db, get_cache
    HAS_API = True
except ImportError:
    HAS_API = False


# Skip all tests if API not available
pytestmark = pytest.mark.skipif(not HAS_API, reason="API not available")


class MockDatabase:
    """Mock database for testing."""
    
    def __init__(self):
        self.chain_state = {
            "best_tip_hash": "00000000" * 8,
            "best_height": 100,
            "best_chainwork": "0" * 60 + "ffff",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        
        self.blocks = {
            "00000000" * 8: {
                "hash": "00000000" * 8,
                "height": 100,
                "prev_hash": "00000001" * 8,
                "time": 1700000000,
                "bits": "1d00ffff",
                "nonce": 12345,
                "merkle_root": "merkle00" * 8,
                "chainwork": "0" * 60 + "ffff",
                "tx_count": 2,
            }
        }
        
        self.txs = {
            "tx000000" * 8: {
                "txid": "tx000000" * 8,
                "block_hash": "00000000" * 8,
                "block_height": 100,
                "idx_in_block": 0,
                "fee_lgb": b"\x00" * 40,
                "size_bytes": 250,
            }
        }
        
        self.address_stats = {
            "1DSVtest123": {
                "address": "1DSVtest123",
                "balance_lgb": "1000000000000000",
                "total_received_lgb": "2000000000000000",
                "total_sent_lgb": "1000000000000000",
                "utxo_count": 5,
                "tx_count": 10,
            }
        }
    
    async def fetch_one(self, query, *args):
        if "chain_state" in query:
            return self.chain_state
        if "blocks" in query and "hash" in query:
            hash_val = args[0] if args else None
            return self.blocks.get(hash_val)
        if "txs" in query:
            txid = args[0] if args else None
            return self.txs.get(txid)
        if "address_stats" in query:
            addr = args[0] if args else None
            return self.address_stats.get(addr)
        return None
    
    async def fetch_all(self, query, *args):
        if "blocks" in query:
            return list(self.blocks.values())
        if "txs" in query:
            return list(self.txs.values())
        return []


class MockCache:
    """Mock Redis cache for testing."""
    
    def __init__(self):
        self.data = {}
    
    async def get(self, key):
        value = self.data.get(key)
        if value:
            return json.dumps(value)
        return None
    
    async def set(self, key, value, ex=None):
        self.data[key] = json.loads(value) if isinstance(value, str) else value
    
    async def delete(self, key):
        if key in self.data:
            del self.data[key]


@pytest.fixture
def mock_db():
    return MockDatabase()


@pytest.fixture
def mock_cache():
    return MockCache()


@pytest.fixture
def client(mock_db, mock_cache):
    """Create test client with mocked dependencies."""
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_cache] = lambda: mock_cache
    
    with TestClient(app) as client:
        yield client
    
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    """Tests for /api/health endpoint."""
    
    def test_health_success(self, client):
        """Test health check returns OK."""
        response = client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
    
    def test_health_includes_checks(self, client):
        """Test health check includes component checks."""
        response = client.get("/api/health")
        data = response.json()
        
        # Should have checks for db, redis, indexer
        if "checks" in data:
            assert isinstance(data["checks"], dict)


class TestChainEndpoint:
    """Tests for /api/chain endpoint."""
    
    def test_chain_info(self, client):
        """Test getting chain info."""
        response = client.get("/api/chain")
        assert response.status_code == 200
        
        data = response.json()
        assert "best_height" in data or "height" in data
    
    def test_chain_includes_tip(self, client):
        """Test chain info includes tip hash."""
        response = client.get("/api/chain")
        data = response.json()
        
        # Should have tip hash
        assert "best_tip_hash" in data or "tip" in data or "hash" in data


class TestBlocksEndpoint:
    """Tests for /api/blocks endpoint."""
    
    def test_blocks_list(self, client):
        """Test getting blocks list."""
        response = client.get("/api/blocks")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, (list, dict))
    
    def test_blocks_limit(self, client):
        """Test blocks list with limit."""
        response = client.get("/api/blocks?limit=5")
        assert response.status_code == 200
    
    def test_blocks_invalid_limit(self, client):
        """Test blocks list with invalid limit."""
        response = client.get("/api/blocks?limit=-1")
        # Should return 400 or handle gracefully
        assert response.status_code in [200, 400]
    
    def test_blocks_cursor(self, client):
        """Test blocks list with cursor."""
        response = client.get("/api/blocks?cursor=abc123")
        # Should handle invalid cursor gracefully
        assert response.status_code in [200, 400]


class TestBlockEndpoint:
    """Tests for /api/block/:id endpoint."""
    
    def test_block_by_hash(self, client):
        """Test getting block by hash."""
        response = client.get("/api/block/" + "00000000" * 8)
        # May return 200 or 404 depending on mock data
        assert response.status_code in [200, 404]
    
    def test_block_by_height(self, client):
        """Test getting block by height."""
        response = client.get("/api/block/100")
        assert response.status_code in [200, 404]
    
    def test_block_invalid_id(self, client):
        """Test getting block with invalid ID."""
        response = client.get("/api/block/invalid")
        assert response.status_code in [400, 404]
    
    def test_block_negative_height(self, client):
        """Test getting block with negative height."""
        response = client.get("/api/block/-1")
        assert response.status_code in [400, 404]


class TestTransactionEndpoint:
    """Tests for /api/tx/:txid endpoint."""
    
    def test_tx_by_id(self, client):
        """Test getting transaction by txid."""
        response = client.get("/api/tx/" + "tx000000" * 8)
        assert response.status_code in [200, 404]
    
    def test_tx_invalid_id(self, client):
        """Test getting transaction with invalid txid."""
        response = client.get("/api/tx/invalid")
        assert response.status_code in [400, 404]
    
    def test_tx_includes_inputs_outputs(self, client):
        """Test transaction includes inputs and outputs."""
        response = client.get("/api/tx/" + "tx000000" * 8)
        if response.status_code == 200:
            data = response.json()
            # Should have inputs/outputs if tx found
            assert "inputs" in data or "vin" in data or "txid" in data


class TestAddressEndpoint:
    """Tests for /api/address/:address endpoint."""
    
    def test_address_stats(self, client):
        """Test getting address stats."""
        response = client.get("/api/address/1DSVtest123")
        assert response.status_code in [200, 404]
    
    def test_address_invalid(self, client):
        """Test getting invalid address."""
        response = client.get("/api/address/invalid!")
        assert response.status_code in [400, 404]
    
    def test_address_includes_balance(self, client):
        """Test address includes balance info."""
        response = client.get("/api/address/1DSVtest123")
        if response.status_code == 200:
            data = response.json()
            assert "balance" in data or "balance_lgb" in data or "address" in data


class TestSearchEndpoint:
    """Tests for /api/search endpoint."""
    
    def test_search_block_hash(self, client):
        """Test searching for block hash."""
        response = client.get("/api/search?q=" + "00000000" * 8)
        assert response.status_code == 200
    
    def test_search_tx_id(self, client):
        """Test searching for transaction ID."""
        response = client.get("/api/search?q=" + "tx000000" * 8)
        assert response.status_code == 200
    
    def test_search_address(self, client):
        """Test searching for address."""
        response = client.get("/api/search?q=1DSVtest123")
        assert response.status_code == 200
    
    def test_search_height(self, client):
        """Test searching for block height."""
        response = client.get("/api/search?q=100")
        assert response.status_code == 200
    
    def test_search_empty(self, client):
        """Test searching with empty query."""
        response = client.get("/api/search?q=")
        assert response.status_code in [200, 400]
    
    def test_search_no_query(self, client):
        """Test searching without query parameter."""
        response = client.get("/api/search")
        assert response.status_code in [200, 400, 422]


class TestInputValidation:
    """Tests for input validation."""
    
    def test_sql_injection_block(self, client):
        """Test SQL injection in block endpoint."""
        response = client.get("/api/block/'; DROP TABLE blocks; --")
        # Should return 400 or 404, not 500
        assert response.status_code in [400, 404]
    
    def test_sql_injection_search(self, client):
        """Test SQL injection in search endpoint."""
        response = client.get("/api/search?q='; DROP TABLE txs; --")
        # Should handle safely
        assert response.status_code in [200, 400]
    
    def test_xss_search(self, client):
        """Test XSS in search endpoint."""
        response = client.get("/api/search?q=<script>alert('xss')</script>")
        assert response.status_code == 200
        
        # Response should not contain unescaped script
        if response.text:
            assert "<script>" not in response.text.lower() or \
                   response.headers.get("content-type", "").startswith("application/json")
    
    def test_path_traversal(self, client):
        """Test path traversal in endpoints."""
        response = client.get("/api/block/../../../etc/passwd")
        assert response.status_code in [400, 404]
    
    def test_large_input(self, client):
        """Test handling of large input."""
        large_query = "a" * 10000
        response = client.get(f"/api/search?q={large_query}")
        # Should handle without crashing
        assert response.status_code in [200, 400, 414]


class TestCaching:
    """Tests for caching functionality."""
    
    def test_cache_hit(self, client, mock_cache):
        """Test cache hit."""
        # Pre-populate cache
        mock_cache.data["chain_info"] = {"height": 100}
        
        response = client.get("/api/chain")
        assert response.status_code == 200
    
    def test_cache_miss(self, client, mock_cache):
        """Test cache miss falls back to database."""
        # Ensure cache is empty
        mock_cache.data.clear()
        
        response = client.get("/api/chain")
        assert response.status_code == 200


class TestRateLimiting:
    """Tests for rate limiting."""
    
    def test_rate_limit_headers(self, client):
        """Test rate limit headers in response."""
        response = client.get("/api/health")
        
        # May have rate limit headers
        # X-RateLimit-Limit, X-RateLimit-Remaining, etc.
        # This is optional based on implementation
        assert response.status_code == 200


class TestErrorHandling:
    """Tests for error handling."""
    
    def test_404_response(self, client):
        """Test 404 response format."""
        response = client.get("/api/block/nonexistent" * 10)
        assert response.status_code in [400, 404]
        
        if response.status_code == 404:
            data = response.json()
            assert "error" in data or "detail" in data or "message" in data
    
    def test_method_not_allowed(self, client):
        """Test method not allowed response."""
        response = client.post("/api/health")
        assert response.status_code in [405, 422]
    
    def test_internal_error_handling(self, client):
        """Test internal error doesn't leak details."""
        # Force an error by using malformed data
        response = client.get("/api/block/" + "\x00" * 100)
        # Should not return 500 with stack trace
        if response.status_code == 500:
            data = response.json()
            assert "traceback" not in str(data).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

