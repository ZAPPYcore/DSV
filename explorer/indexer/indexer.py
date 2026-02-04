#!/usr/bin/env python3
"""
DSV Block Explorer Indexer

Reorg-safe blockchain indexer that follows the best chain via chainwork.
"""
import time
import signal
import sys
import json
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import redis
import requests
import structlog
from prometheus_client import start_http_server, Counter, Gauge, Histogram

from config import config

# Logging setup
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
log = structlog.get_logger()

# Prometheus metrics
BLOCKS_INDEXED = Counter('dsv_indexer_blocks_indexed_total', 'Total blocks indexed')
TXNS_INDEXED = Counter('dsv_indexer_txns_indexed_total', 'Total transactions indexed')
REORGS = Counter('dsv_indexer_reorgs_total', 'Total chain reorganizations')
CURRENT_HEIGHT = Gauge('dsv_indexer_current_height', 'Current indexed height')
INDEX_LAG = Gauge('dsv_indexer_lag_blocks', 'Blocks behind node tip')
INDEX_TIME = Histogram('dsv_indexer_block_time_seconds', 'Time to index a block')


@dataclass
class Block:
    hash: str
    height: int
    prev_hash: str
    time: int
    bits: int
    nonce: int
    merkle: str
    chainwork: str
    tx_count: int
    txids: List[str]
    size: int = 0


@dataclass  
class Transaction:
    txid: str
    block_hash: str
    block_height: int
    idx_in_block: int
    inputs: List[Dict]
    outputs: List[Dict]
    size: int
    fee: bytes  # 40-byte u320


class RPCClient:
    """JSON-RPC client for DSV node."""
    
    def __init__(self, url: str, auth_token: str):
        self.url = url
        self.auth_token = auth_token
        self.session = requests.Session()
        self.session.headers['Content-Type'] = 'application/json'
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
    
    def call(self, method: str, params: List = None) -> Any:
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or [],
            'id': 1
        }
        
        try:
            resp = self.session.post(self.url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            if 'error' in data and data['error']:
                raise Exception(f"RPC error: {data['error']}")
            
            return data.get('result')
        except requests.RequestException as e:
            log.error("rpc_error", method=method, error=str(e))
            raise
    
    def get_blockchain_info(self) -> Dict:
        return self.call('getblockchaininfo')
    
    def get_block_hash(self, height: int) -> str:
        return self.call('getblockhash', [height])
    
    def get_block(self, hash: str) -> Dict:
        return self.call('getblock', [hash])
    
    def get_raw_transaction(self, txid: str) -> str:
        return self.call('getrawtransaction', [txid])


class Database:
    """PostgreSQL database interface."""
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.conn = None
    
    def connect(self):
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = False
    
    def close(self):
        if self.conn:
            self.conn.close()
    
    @contextmanager
    def cursor(self):
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
        finally:
            cur.close()
    
    def commit(self):
        self.conn.commit()
    
    def rollback(self):
        self.conn.rollback()
    
    def get_chain_state(self) -> Tuple[str, int, str]:
        """Get current indexed chain state."""
        with self.cursor() as cur:
            cur.execute("SELECT best_tip_hash, best_height, best_chainwork FROM chain_state WHERE id = 1")
            row = cur.fetchone()
            if row:
                return (
                    row['best_tip_hash'].hex() if row['best_tip_hash'] else '0' * 64,
                    row['best_height'],
                    row['best_chainwork'].hex() if row['best_chainwork'] else '0' * 64
                )
            return '0' * 64, -1, '0' * 64
    
    def update_chain_state(self, hash: str, height: int, chainwork: str):
        """Update chain state."""
        with self.cursor() as cur:
            cur.execute("""
                UPDATE chain_state 
                SET best_tip_hash = %s, best_height = %s, best_chainwork = %s, updated_at = NOW()
                WHERE id = 1
            """, (bytes.fromhex(hash), height, bytes.fromhex(chainwork)))
    
    def get_block_at_height(self, height: int) -> Optional[Dict]:
        """Get block at height."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM blocks WHERE height = %s", (height,))
            return cur.fetchone()
    
    def get_block_by_hash(self, hash: str) -> Optional[Dict]:
        """Get block by hash."""
        with self.cursor() as cur:
            cur.execute("SELECT * FROM blocks WHERE hash = %s", (bytes.fromhex(hash),))
            return cur.fetchone()
    
    def insert_block(self, block: Block):
        """Insert a block."""
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO blocks (hash, height, prev_hash, time, bits, nonce, merkle, 
                                    chainwork, file_no, file_offset, tx_count, size_bytes)
                VALUES (%s, %s, %s, to_timestamp(%s), %s, %s, %s, %s, 0, 0, %s, %s)
                ON CONFLICT (hash) DO NOTHING
            """, (
                bytes.fromhex(block.hash),
                block.height,
                bytes.fromhex(block.prev_hash),
                block.time,
                block.bits,
                block.nonce,
                bytes.fromhex(block.merkle),
                bytes.fromhex(block.chainwork),
                block.tx_count,
                block.size
            ))
    
    def insert_transaction(self, tx: Transaction):
        """Insert a transaction with inputs and outputs."""
        with self.cursor() as cur:
            # Insert transaction
            cur.execute("""
                INSERT INTO txs (txid, block_hash, block_height, idx_in_block, fee_lgb, size_bytes)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (txid) DO NOTHING
            """, (
                bytes.fromhex(tx.txid),
                bytes.fromhex(tx.block_hash),
                tx.block_height,
                tx.idx_in_block,
                tx.fee,
                tx.size
            ))
            
            # Insert inputs
            for inp in tx.inputs:
                cur.execute("""
                    INSERT INTO tx_inputs (txid, n, prev_txid, prev_vout, address, amount_lgb, is_coinbase)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (txid, n) DO NOTHING
                """, (
                    bytes.fromhex(tx.txid),
                    inp['n'],
                    bytes.fromhex(inp['prev_txid']),
                    inp['prev_vout'],
                    inp.get('address'),
                    inp.get('amount'),
                    inp.get('is_coinbase', False)
                ))
                
                # Mark previous output as spent
                if not inp.get('is_coinbase'):
                    cur.execute("""
                        UPDATE tx_outputs 
                        SET spent_by_txid = %s, spent_at_height = %s
                        WHERE txid = %s AND n = %s
                    """, (
                        bytes.fromhex(tx.txid),
                        tx.block_height,
                        bytes.fromhex(inp['prev_txid']),
                        inp['prev_vout']
                    ))
            
            # Insert outputs
            for out in tx.outputs:
                cur.execute("""
                    INSERT INTO tx_outputs (txid, n, address, amount_lgb)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (txid, n) DO NOTHING
                """, (
                    bytes.fromhex(tx.txid),
                    out['n'],
                    out['address'],
                    out['amount']
                ))
    
    def update_address_stats(self, address: str, received: bytes = None, sent: bytes = None,
                             utxo_delta: int = 0, tx_delta: int = 0, height: int = None):
        """Update address statistics."""
        with self.cursor() as cur:
            # Ensure address exists
            cur.execute("""
                INSERT INTO address_stats (address, first_seen_height, last_seen_height)
                VALUES (%s, %s, %s)
                ON CONFLICT (address) DO UPDATE SET last_seen_height = EXCLUDED.last_seen_height
            """, (address, height, height))
            
            if received:
                cur.execute("""
                    UPDATE address_stats 
                    SET total_received_lgb = u320_add(total_received_lgb, %s),
                        balance_lgb = u320_add(balance_lgb, %s),
                        updated_at = NOW()
                    WHERE address = %s
                """, (received, received, address))
            
            if sent:
                cur.execute("""
                    UPDATE address_stats 
                    SET total_sent_lgb = u320_add(total_sent_lgb, %s),
                        balance_lgb = u320_sub(balance_lgb, %s),
                        updated_at = NOW()
                    WHERE address = %s
                """, (sent, sent, address))
            
            if utxo_delta != 0:
                cur.execute("""
                    UPDATE address_stats 
                    SET utxo_count = utxo_count + %s,
                        updated_at = NOW()
                    WHERE address = %s
                """, (utxo_delta, address))
            
            if tx_delta != 0:
                cur.execute("""
                    UPDATE address_stats 
                    SET tx_count = tx_count + %s,
                        updated_at = NOW()
                    WHERE address = %s
                """, (tx_delta, address))
    
    def delete_block(self, hash: str):
        """Delete a block and all its transactions (cascade)."""
        with self.cursor() as cur:
            cur.execute("DELETE FROM blocks WHERE hash = %s", (bytes.fromhex(hash),))
    
    def log_reorg(self, from_hash: str, to_hash: str, from_height: int, to_height: int,
                  detached: int, attached: int):
        """Log a reorg event."""
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO reorg_log (from_hash, to_hash, from_height, to_height, 
                                       detached_count, attached_count)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                bytes.fromhex(from_hash),
                bytes.fromhex(to_hash),
                from_height,
                to_height,
                detached,
                attached
            ))


class Cache:
    """Redis cache interface."""
    
    def __init__(self, url: str):
        self.client = redis.from_url(url)
    
    def get(self, key: str) -> Optional[str]:
        return self.client.get(key)
    
    def set(self, key: str, value: str, ttl: int = 60):
        self.client.setex(key, ttl, value)
    
    def delete(self, key: str):
        self.client.delete(key)
    
    def invalidate_block(self, hash: str, height: int):
        """Invalidate block-related cache entries."""
        self.delete(f"block:{hash}")
        self.delete(f"block:height:{height}")
        self.delete("chain:info")
    
    def invalidate_address(self, address: str):
        """Invalidate address-related cache entries."""
        self.delete(f"address:{address}")
        self.delete(f"address:{address}:utxos")


class Indexer:
    """Main indexer class."""
    
    def __init__(self):
        self.rpc = RPCClient(config.rpc_url, config.rpc_auth)
        self.db = Database(config.db_dsn)
        self.cache = Cache(config.redis_url)
        self.running = False
    
    def start(self):
        """Start the indexer."""
        log.info("indexer_starting")
        self.db.connect()
        self.running = True
        
        # Start metrics server
        start_http_server(config.metrics_port)
        log.info("metrics_server_started", port=config.metrics_port)
        
        # Main indexing loop
        while self.running:
            try:
                self.sync()
            except Exception as e:
                log.error("sync_error", error=str(e))
                self.db.rollback()
            
            time.sleep(config.poll_interval)
    
    def stop(self):
        """Stop the indexer."""
        log.info("indexer_stopping")
        self.running = False
        self.db.close()
    
    def sync(self):
        """Synchronize with the node."""
        # Get node status
        info = self.rpc.get_blockchain_info()
        node_height = info['blocks']
        node_tip = info['bestblockhash']
        
        # Get our status
        our_tip, our_height, our_chainwork = self.db.get_chain_state()
        
        INDEX_LAG.set(node_height - our_height)
        
        if node_tip == our_tip:
            return  # Already synced
        
        # Check for reorg
        if our_height >= 0:
            reorg_point = self.find_reorg_point(our_height, our_tip)
            if reorg_point is not None and reorg_point < our_height:
                self.handle_reorg(reorg_point, our_height, our_tip)
                our_height = reorg_point
        
        # Index new blocks
        start_height = our_height + 1
        for height in range(start_height, node_height + 1):
            with INDEX_TIME.time():
                self.index_block_at_height(height)
            
            if height % 100 == 0:
                log.info("index_progress", height=height, target=node_height)
    
    def find_reorg_point(self, our_height: int, our_tip: str) -> Optional[int]:
        """Find the point where our chain diverged from the node's chain."""
        check_depth = min(config.reorg_depth, our_height + 1)
        
        for offset in range(check_depth):
            height = our_height - offset
            our_block = self.db.get_block_at_height(height)
            
            if our_block:
                our_hash = our_block['hash'].hex()
                node_hash = self.rpc.get_block_hash(height)
                
                if our_hash == node_hash:
                    return height
        
        return 0  # Full resync needed
    
    def handle_reorg(self, reorg_point: int, old_height: int, old_tip: str):
        """Handle a chain reorganization."""
        log.warn("reorg_detected", reorg_point=reorg_point, old_height=old_height)
        REORGS.inc()
        
        # Delete blocks from reorg_point + 1 to old_height
        for height in range(old_height, reorg_point, -1):
            block = self.db.get_block_at_height(height)
            if block:
                block_hash = block['hash'].hex()
                self.db.delete_block(block_hash)
                self.cache.invalidate_block(block_hash, height)
                log.info("block_disconnected", height=height, hash=block_hash)
        
        # Get new tip info
        new_tip = self.rpc.get_block_hash(reorg_point)
        
        # Log reorg
        self.db.log_reorg(old_tip, new_tip, old_height, reorg_point,
                          old_height - reorg_point, 0)
        
        # Update chain state
        new_block = self.rpc.get_block(new_tip)
        self.db.update_chain_state(new_tip, reorg_point, 
                                   new_block.get('chainwork', '0' * 64))
        self.db.commit()
    
    def index_block_at_height(self, height: int):
        """Index a block at a specific height."""
        block_hash = self.rpc.get_block_hash(height)
        block_data = self.rpc.get_block(block_hash)
        
        # Create block object
        block = Block(
            hash=block_data['hash'],
            height=height,
            prev_hash=block_data.get('previousblockhash', '0' * 64),
            time=block_data['time'],
            bits=block_data['bits'],
            nonce=block_data['nonce'],
            merkle=block_data['merkleroot'],
            chainwork=block_data.get('chainwork', '0' * 64),
            tx_count=block_data.get('nTx', len(block_data.get('tx', []))),
            txids=block_data.get('tx', [])
        )
        
        # Insert block
        self.db.insert_block(block)
        BLOCKS_INDEXED.inc()
        
        # Index transactions
        for idx, txid in enumerate(block.txids):
            self.index_transaction(txid, block_hash, height, idx)
        
        # Update chain state
        self.db.update_chain_state(block_hash, height, block.chainwork)
        self.db.commit()
        
        CURRENT_HEIGHT.set(height)
        
        # Invalidate cache
        self.cache.invalidate_block(block_hash, height)
        
        log.info("block_indexed", height=height, hash=block_hash[:16] + "...",
                 txs=block.tx_count)
    
    def index_transaction(self, txid: str, block_hash: str, height: int, idx: int):
        """Index a transaction."""
        # Note: In production, we'd get full tx data from RPC
        # For now, we create a minimal transaction record
        
        zero_amount = b'\x00' * 40  # 320-bit zero
        
        tx = Transaction(
            txid=txid,
            block_hash=block_hash,
            block_height=height,
            idx_in_block=idx,
            inputs=[{
                'n': 0,
                'prev_txid': '0' * 64,
                'prev_vout': 0xFFFFFFFF if idx == 0 else 0,
                'is_coinbase': idx == 0
            }],
            outputs=[{
                'n': 0,
                'address': 'unknown',
                'amount': zero_amount
            }],
            size=250,  # Estimated
            fee=zero_amount
        )
        
        self.db.insert_transaction(tx)
        TXNS_INDEXED.inc()


def main():
    indexer = Indexer()
    
    def signal_handler(sig, frame):
        log.info("shutdown_signal_received")
        indexer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        indexer.start()
    except KeyboardInterrupt:
        indexer.stop()


if __name__ == '__main__':
    main()

