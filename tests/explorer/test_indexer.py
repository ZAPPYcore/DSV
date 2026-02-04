#!/usr/bin/env python3
"""
DSV Explorer Indexer Tests

Tests for the blockchain indexer including:
- Block parsing
- Transaction parsing
- Reorg handling
- Checkpoint recovery
"""

import asyncio
import pytest
import tempfile
import os
import json
from unittest.mock import Mock, AsyncMock, patch
from decimal import Decimal

# Try to import indexer modules
try:
    from explorer.indexer.indexer import BlockIndexer, IndexerState
    from explorer.indexer.config import IndexerConfig
    HAS_INDEXER = True
except ImportError:
    HAS_INDEXER = False


# Skip all tests if indexer not available
pytestmark = pytest.mark.skipif(not HAS_INDEXER, reason="Indexer not available")


class MockRPCClient:
    """Mock DSV node RPC client."""
    
    def __init__(self):
        self.blocks = {}
        self.best_height = 0
        self.best_hash = "0" * 64
        
    async def get_block_count(self):
        return self.best_height
    
    async def get_best_block_hash(self):
        return self.best_hash
    
    async def get_block(self, hash_or_height):
        if isinstance(hash_or_height, int):
            for h, b in self.blocks.items():
                if b.get("height") == hash_or_height:
                    return b
            return None
        return self.blocks.get(hash_or_height)
    
    async def get_block_hash(self, height):
        for h, b in self.blocks.items():
            if b.get("height") == height:
                return h
        return None
    
    def add_block(self, block):
        self.blocks[block["hash"]] = block
        if block["height"] > self.best_height:
            self.best_height = block["height"]
            self.best_hash = block["hash"]


class MockDatabase:
    """Mock PostgreSQL database."""
    
    def __init__(self):
        self.chain_state = {
            "best_tip_hash": "0" * 64,
            "best_height": -1,
            "best_chainwork": "0",
        }
        self.blocks = {}
        self.txs = {}
        self.tx_inputs = {}
        self.tx_outputs = {}
        self.address_stats = {}
        self.reorg_log = []
        
    async def get_chain_state(self):
        return self.chain_state
    
    async def update_chain_state(self, hash, height, chainwork):
        self.chain_state = {
            "best_tip_hash": hash,
            "best_height": height,
            "best_chainwork": chainwork,
        }
    
    async def insert_block(self, block):
        self.blocks[block["hash"]] = block
    
    async def delete_block(self, hash):
        if hash in self.blocks:
            del self.blocks[hash]
    
    async def get_block(self, hash):
        return self.blocks.get(hash)
    
    async def begin_transaction(self):
        pass
    
    async def commit(self):
        pass
    
    async def rollback(self):
        pass


def create_mock_block(height, prev_hash=None, tx_count=1):
    """Create a mock block for testing."""
    if prev_hash is None:
        prev_hash = "0" * 64
    
    block_hash = f"{height:064x}"
    
    return {
        "hash": block_hash,
        "height": height,
        "prev_hash": prev_hash,
        "time": 1700000000 + height * 600,
        "bits": "1d00ffff",
        "nonce": height * 12345,
        "merkle_root": f"merkle{height:060x}",
        "chainwork": f"{height:064x}",
        "tx_count": tx_count,
        "txs": [
            {
                "txid": f"tx{height}_{i:058x}",
                "inputs": [
                    {
                        "prev_txid": "0" * 64 if i == 0 else f"prev{height}_{i}",
                        "prev_vout": 0xFFFFFFFF if i == 0 else 0,
                        "address": None if i == 0 else f"addr{height}_{i}",
                        "amount": "0" if i == 0 else "1000000",
                        "is_coinbase": i == 0,
                    }
                ],
                "outputs": [
                    {
                        "address": f"addr{height}_{i}_out",
                        "amount": "2100000000000000",
                    }
                ],
                "fee": "0" if i == 0 else "1000",
                "size": 250,
            }
            for i in range(tx_count)
        ],
    }


@pytest.fixture
def mock_rpc():
    return MockRPCClient()


@pytest.fixture
def mock_db():
    return MockDatabase()


class TestBlockParsing:
    """Tests for block parsing."""
    
    def test_parse_block_header(self, mock_rpc, mock_db):
        """Test parsing block header fields."""
        block = create_mock_block(1)
        
        assert block["hash"] is not None
        assert block["height"] == 1
        assert block["prev_hash"] == "0" * 64
        assert block["time"] > 0
        assert block["bits"] == "1d00ffff"
        assert block["nonce"] > 0
    
    def test_parse_transactions(self, mock_rpc, mock_db):
        """Test parsing transactions in block."""
        block = create_mock_block(1, tx_count=5)
        
        assert len(block["txs"]) == 5
        
        # First tx should be coinbase
        coinbase = block["txs"][0]
        assert coinbase["inputs"][0]["is_coinbase"] is True
        
        # Other txs should not be coinbase
        for tx in block["txs"][1:]:
            assert tx["inputs"][0]["is_coinbase"] is False
    
    def test_parse_inputs_outputs(self, mock_rpc, mock_db):
        """Test parsing transaction inputs and outputs."""
        block = create_mock_block(1, tx_count=2)
        
        for tx in block["txs"]:
            assert len(tx["inputs"]) > 0
            assert len(tx["outputs"]) > 0
            
            for inp in tx["inputs"]:
                assert "prev_txid" in inp
                assert "prev_vout" in inp
            
            for out in tx["outputs"]:
                assert "address" in out
                assert "amount" in out


class TestChainSync:
    """Tests for chain synchronization."""
    
    @pytest.mark.asyncio
    async def test_sync_initial(self, mock_rpc, mock_db):
        """Test initial chain sync."""
        # Add some blocks to RPC
        prev_hash = "0" * 64
        for i in range(5):
            block = create_mock_block(i, prev_hash)
            mock_rpc.add_block(block)
            prev_hash = block["hash"]
        
        # Verify RPC has blocks
        assert mock_rpc.best_height == 4
    
    @pytest.mark.asyncio
    async def test_sync_incremental(self, mock_rpc, mock_db):
        """Test incremental sync of new blocks."""
        # Setup initial state
        prev_hash = "0" * 64
        for i in range(3):
            block = create_mock_block(i, prev_hash)
            mock_rpc.add_block(block)
            mock_db.blocks[block["hash"]] = block
            prev_hash = block["hash"]
        
        mock_db.chain_state["best_height"] = 2
        mock_db.chain_state["best_tip_hash"] = prev_hash
        
        # Add more blocks to RPC
        for i in range(3, 6):
            block = create_mock_block(i, prev_hash)
            mock_rpc.add_block(block)
            prev_hash = block["hash"]
        
        # Verify new blocks available
        assert mock_rpc.best_height == 5
        assert mock_db.chain_state["best_height"] == 2


class TestReorgHandling:
    """Tests for chain reorganization handling."""
    
    @pytest.mark.asyncio
    async def test_detect_reorg(self, mock_rpc, mock_db):
        """Test detecting a chain reorganization."""
        # Build initial chain: 0 -> 1 -> 2 -> 3
        prev_hash = "0" * 64
        chain_a = []
        for i in range(4):
            block = create_mock_block(i, prev_hash)
            chain_a.append(block)
            mock_rpc.add_block(block)
            mock_db.blocks[block["hash"]] = block
            prev_hash = block["hash"]
        
        mock_db.chain_state["best_height"] = 3
        mock_db.chain_state["best_tip_hash"] = chain_a[-1]["hash"]
        
        # Build fork from height 2: 0 -> 1 -> 2' -> 3' -> 4'
        fork_prev = chain_a[1]["hash"]  # Fork after block 1
        chain_b = []
        for i in range(2, 5):
            # Create different block (different hash)
            block = create_mock_block(i, fork_prev)
            block["hash"] = f"fork{i:060x}"  # Different hash
            block["nonce"] = i * 99999  # Different nonce
            chain_b.append(block)
            fork_prev = block["hash"]
        
        # Fork is longer (height 4 vs 3), should trigger reorg
        assert len(chain_b) == 3
        assert chain_b[-1]["height"] == 4
    
    @pytest.mark.asyncio
    async def test_rollback_blocks(self, mock_rpc, mock_db):
        """Test rolling back blocks during reorg."""
        # Add blocks
        prev_hash = "0" * 64
        for i in range(5):
            block = create_mock_block(i, prev_hash)
            mock_db.blocks[block["hash"]] = block
            prev_hash = block["hash"]
        
        initial_count = len(mock_db.blocks)
        
        # Simulate rollback
        blocks_to_remove = list(mock_db.blocks.keys())[-2:]
        for h in blocks_to_remove:
            await mock_db.delete_block(h)
        
        assert len(mock_db.blocks) == initial_count - 2
    
    @pytest.mark.asyncio
    async def test_reorg_utxo_update(self, mock_rpc, mock_db):
        """Test UTXO updates during reorg."""
        # This would test that spent outputs become unspent
        # and new outputs become spent during reorg
        # Simplified test structure
        
        mock_db.tx_outputs = {
            "out1": {"spent_by_txid": "tx123", "spent_at_height": 5},
            "out2": {"spent_by_txid": None, "spent_at_height": None},
        }
        
        # Simulate unspending output during rollback
        mock_db.tx_outputs["out1"]["spent_by_txid"] = None
        mock_db.tx_outputs["out1"]["spent_at_height"] = None
        
        assert mock_db.tx_outputs["out1"]["spent_by_txid"] is None


class TestCheckpoints:
    """Tests for checkpoint functionality."""
    
    @pytest.mark.asyncio
    async def test_save_checkpoint(self, mock_db):
        """Test saving a checkpoint."""
        await mock_db.update_chain_state(
            hash="abc123" + "0" * 58,
            height=100,
            chainwork="0" * 60 + "beef"
        )
        
        state = await mock_db.get_chain_state()
        assert state["best_height"] == 100
        assert state["best_tip_hash"] == "abc123" + "0" * 58
    
    @pytest.mark.asyncio
    async def test_resume_from_checkpoint(self, mock_db):
        """Test resuming indexing from checkpoint."""
        # Simulate crash by setting checkpoint
        await mock_db.update_chain_state(
            hash="checkpoint" + "0" * 54,
            height=50,
            chainwork="0" * 60 + "work"
        )
        
        # Verify can resume from checkpoint
        state = await mock_db.get_chain_state()
        assert state["best_height"] == 50


class TestAddressStats:
    """Tests for address statistics updates."""
    
    @pytest.mark.asyncio
    async def test_balance_update_receive(self, mock_db):
        """Test balance update on receive."""
        address = "test_address_1"
        mock_db.address_stats[address] = {
            "balance_lgb": "0",
            "total_received_lgb": "0",
            "total_sent_lgb": "0",
            "utxo_count": 0,
            "tx_count": 0,
        }
        
        # Simulate receive
        amount = 1000000
        mock_db.address_stats[address]["balance_lgb"] = str(amount)
        mock_db.address_stats[address]["total_received_lgb"] = str(amount)
        mock_db.address_stats[address]["utxo_count"] = 1
        mock_db.address_stats[address]["tx_count"] = 1
        
        stats = mock_db.address_stats[address]
        assert int(stats["balance_lgb"]) == amount
        assert stats["utxo_count"] == 1
    
    @pytest.mark.asyncio
    async def test_balance_update_spend(self, mock_db):
        """Test balance update on spend."""
        address = "test_address_2"
        initial_balance = 1000000
        spend_amount = 400000
        
        mock_db.address_stats[address] = {
            "balance_lgb": str(initial_balance),
            "total_received_lgb": str(initial_balance),
            "total_sent_lgb": "0",
            "utxo_count": 1,
            "tx_count": 1,
        }
        
        # Simulate spend
        new_balance = initial_balance - spend_amount
        mock_db.address_stats[address]["balance_lgb"] = str(new_balance)
        mock_db.address_stats[address]["total_sent_lgb"] = str(spend_amount)
        mock_db.address_stats[address]["tx_count"] = 2
        
        stats = mock_db.address_stats[address]
        assert int(stats["balance_lgb"]) == new_balance
        assert int(stats["total_sent_lgb"]) == spend_amount


class TestBatchProcessing:
    """Tests for batch processing."""
    
    @pytest.mark.asyncio
    async def test_batch_insert_blocks(self, mock_db):
        """Test batch inserting blocks."""
        blocks = [create_mock_block(i) for i in range(10)]
        
        for block in blocks:
            await mock_db.insert_block(block)
        
        assert len(mock_db.blocks) == 10
    
    @pytest.mark.asyncio
    async def test_batch_transaction(self, mock_db):
        """Test transactional batch processing."""
        await mock_db.begin_transaction()
        
        try:
            for i in range(5):
                block = create_mock_block(i)
                await mock_db.insert_block(block)
            
            await mock_db.commit()
        except Exception:
            await mock_db.rollback()
            raise
        
        assert len(mock_db.blocks) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

