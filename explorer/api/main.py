#!/usr/bin/env python3
"""
DSV Block Explorer API

Production-grade REST API for blockchain data.
"""
import os
from typing import Optional, List, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import psycopg2
import psycopg2.extras
import redis
import structlog
from dotenv import load_dotenv

load_dotenv()

# Configuration
DB_DSN = os.getenv("DB_DSN", "host=localhost dbname=dsv_explorer user=dsv_explorer")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))

# Logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
log = structlog.get_logger()

# Security
security = HTTPBearer(auto_error=False)

# Database pool
db_pool = None
redis_client = None


def get_db():
    """Get database connection."""
    conn = psycopg2.connect(DB_DSN)
    try:
        yield conn
    finally:
        conn.close()


def get_cache():
    """Get Redis client."""
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(REDIS_URL)
    return redis_client


def verify_admin(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify admin authentication."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="Admin token not configured")
    if not credentials or credentials.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    return True


# ============================================================================
# Pydantic Models
# ============================================================================

class ChainInfo(BaseModel):
    best_tip_hash: str
    best_height: int
    best_chainwork: str
    updated_at: str


class BlockSummary(BaseModel):
    hash: str
    height: int
    time: str
    tx_count: int


class BlockDetail(BaseModel):
    hash: str
    height: int
    prev_hash: str
    time: str
    bits: int
    nonce: int
    merkle: str
    chainwork: str
    tx_count: int
    size_bytes: int
    confirmations: int
    txids: List[str] = []


class TransactionSummary(BaseModel):
    txid: str
    block_height: int
    idx_in_block: int
    fee: str
    size_bytes: int


class TransactionInput(BaseModel):
    n: int
    prev_txid: str
    prev_vout: int
    address: Optional[str]
    amount: Optional[str]
    is_coinbase: bool


class TransactionOutput(BaseModel):
    n: int
    address: str
    amount: str
    spent_by: Optional[str]
    spent_at_height: Optional[int]


class TransactionDetail(BaseModel):
    txid: str
    block_hash: str
    block_height: int
    idx_in_block: int
    fee: str
    size_bytes: int
    confirmations: int
    inputs: List[TransactionInput]
    outputs: List[TransactionOutput]


class AddressInfo(BaseModel):
    address: str
    balance: str
    total_received: str
    total_sent: str
    utxo_count: int
    tx_count: int
    first_seen_height: Optional[int]
    last_seen_height: Optional[int]


class UTXO(BaseModel):
    txid: str
    vout: int
    amount: str
    height: int


class SearchResult(BaseModel):
    type: str  # 'block', 'transaction', 'address'
    value: str


class HealthCheck(BaseModel):
    status: str
    db: str
    cache: str
    indexer_height: int


# ============================================================================
# Helper Functions
# ============================================================================

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hex string."""
    return b.hex() if b else ""


def u320_to_str(b: bytes) -> str:
    """Convert 40-byte u320 to decimal string."""
    if not b or len(b) != 40:
        return "0"
    
    # Little-endian to big int
    value = int.from_bytes(b, byteorder='little', signed=False)
    return str(value)


def format_dsv(lgb_str: str) -> str:
    """Format LGB amount as DSV."""
    # 1 DSV = 10^72 LGB
    try:
        value = int(lgb_str)
        if value == 0:
            return "0"
        
        # This is a placeholder - proper formatting would need big decimal
        return lgb_str
    except (ValueError, TypeError):
        return "0"


# ============================================================================
# Application Setup
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    log.info("api_starting")
    yield
    log.info("api_stopping")


app = FastAPI(
    title="DSV Block Explorer API",
    description="REST API for DSV blockchain data",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/api/health", response_model=HealthCheck)
async def health_check(conn=Depends(get_db)):
    """Health check endpoint."""
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT best_height FROM chain_state WHERE id = 1")
            row = cur.fetchone()
            height = row[0] if row else -1
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
        height = -1
    
    try:
        cache = get_cache()
        cache.ping()
        cache_status = "ok"
    except Exception as e:
        cache_status = f"error: {str(e)}"
    
    return HealthCheck(
        status="ok" if db_status == "ok" and cache_status == "ok" else "degraded",
        db=db_status,
        cache=cache_status,
        indexer_height=height
    )


@app.get("/api/chain", response_model=ChainInfo)
async def get_chain_info(conn=Depends(get_db)):
    """Get current chain state."""
    cache = get_cache()
    cached = cache.get("chain:info")
    if cached:
        import json
        return ChainInfo(**json.loads(cached))
    
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT best_tip_hash, best_height, best_chainwork, updated_at
            FROM chain_state WHERE id = 1
        """)
        row = cur.fetchone()
    
    if not row:
        raise HTTPException(status_code=500, detail="Chain state not found")
    
    result = ChainInfo(
        best_tip_hash=bytes_to_hex(row['best_tip_hash']),
        best_height=row['best_height'],
        best_chainwork=bytes_to_hex(row['best_chainwork']),
        updated_at=row['updated_at'].isoformat()
    )
    
    import json
    cache.setex("chain:info", CACHE_TTL, json.dumps(result.model_dump()))
    
    return result


@app.get("/api/blocks", response_model=List[BlockSummary])
async def get_blocks(
    limit: int = Query(default=10, ge=1, le=100),
    cursor: Optional[int] = Query(default=None),
    conn=Depends(get_db)
):
    """Get recent blocks with pagination."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if cursor is not None:
            cur.execute("""
                SELECT hash, height, time, tx_count 
                FROM blocks 
                WHERE height < %s
                ORDER BY height DESC 
                LIMIT %s
            """, (cursor, limit))
        else:
            cur.execute("""
                SELECT hash, height, time, tx_count 
                FROM blocks 
                ORDER BY height DESC 
                LIMIT %s
            """, (limit,))
        
        rows = cur.fetchall()
    
    return [
        BlockSummary(
            hash=bytes_to_hex(row['hash']),
            height=row['height'],
            time=row['time'].isoformat(),
            tx_count=row['tx_count']
        )
        for row in rows
    ]


@app.get("/api/block/{block_id}", response_model=BlockDetail)
async def get_block(block_id: str, conn=Depends(get_db)):
    """Get block by hash or height."""
    cache = get_cache()
    cached = cache.get(f"block:{block_id}")
    if cached:
        import json
        return BlockDetail(**json.loads(cached))
    
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Try as height first
        try:
            height = int(block_id)
            cur.execute("SELECT * FROM blocks WHERE height = %s", (height,))
        except ValueError:
            # Try as hash
            try:
                hash_bytes = bytes.fromhex(block_id)
                cur.execute("SELECT * FROM blocks WHERE hash = %s", (hash_bytes,))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid block identifier")
        
        row = cur.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Block not found")
    
    # Get current height for confirmations
    chain_info = await get_chain_info(conn)
    confirmations = chain_info.best_height - row['height'] + 1
    
    # Get transaction IDs
    with conn.cursor() as cur:
        cur.execute("""
            SELECT txid FROM txs WHERE block_hash = %s ORDER BY idx_in_block
        """, (row['hash'],))
        txids = [bytes_to_hex(r[0]) for r in cur.fetchall()]
    
    result = BlockDetail(
        hash=bytes_to_hex(row['hash']),
        height=row['height'],
        prev_hash=bytes_to_hex(row['prev_hash']),
        time=row['time'].isoformat(),
        bits=row['bits'],
        nonce=row['nonce'],
        merkle=bytes_to_hex(row['merkle']),
        chainwork=bytes_to_hex(row['chainwork']),
        tx_count=row['tx_count'],
        size_bytes=row['size_bytes'],
        confirmations=confirmations,
        txids=txids
    )
    
    import json
    cache.setex(f"block:{block_id}", CACHE_TTL, json.dumps(result.model_dump()))
    
    return result


@app.get("/api/tx/{txid}", response_model=TransactionDetail)
async def get_transaction(txid: str, conn=Depends(get_db)):
    """Get transaction by ID."""
    try:
        txid_bytes = bytes.fromhex(txid)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid transaction ID")
    
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM txs WHERE txid = %s", (txid_bytes,))
        tx_row = cur.fetchone()
    
    if not tx_row:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    # Get inputs
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT n, prev_txid, prev_vout, address, amount_lgb, is_coinbase
            FROM tx_inputs WHERE txid = %s ORDER BY n
        """, (txid_bytes,))
        input_rows = cur.fetchall()
    
    # Get outputs
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT n, address, amount_lgb, spent_by_txid, spent_at_height
            FROM tx_outputs WHERE txid = %s ORDER BY n
        """, (txid_bytes,))
        output_rows = cur.fetchall()
    
    # Get confirmations
    chain_info = await get_chain_info(conn)
    confirmations = chain_info.best_height - tx_row['block_height'] + 1
    
    return TransactionDetail(
        txid=txid,
        block_hash=bytes_to_hex(tx_row['block_hash']),
        block_height=tx_row['block_height'],
        idx_in_block=tx_row['idx_in_block'],
        fee=u320_to_str(tx_row['fee_lgb']),
        size_bytes=tx_row['size_bytes'],
        confirmations=confirmations,
        inputs=[
            TransactionInput(
                n=r['n'],
                prev_txid=bytes_to_hex(r['prev_txid']),
                prev_vout=r['prev_vout'],
                address=r['address'],
                amount=u320_to_str(r['amount_lgb']) if r['amount_lgb'] else None,
                is_coinbase=r['is_coinbase']
            )
            for r in input_rows
        ],
        outputs=[
            TransactionOutput(
                n=r['n'],
                address=r['address'],
                amount=u320_to_str(r['amount_lgb']),
                spent_by=bytes_to_hex(r['spent_by_txid']) if r['spent_by_txid'] else None,
                spent_at_height=r['spent_at_height']
            )
            for r in output_rows
        ]
    )


@app.get("/api/address/{address}", response_model=AddressInfo)
async def get_address(address: str, conn=Depends(get_db)):
    """Get address information."""
    cache = get_cache()
    cached = cache.get(f"address:{address}")
    if cached:
        import json
        return AddressInfo(**json.loads(cached))
    
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM address_stats WHERE address = %s", (address,))
        row = cur.fetchone()
    
    if not row:
        # Address not seen yet
        return AddressInfo(
            address=address,
            balance="0",
            total_received="0",
            total_sent="0",
            utxo_count=0,
            tx_count=0,
            first_seen_height=None,
            last_seen_height=None
        )
    
    result = AddressInfo(
        address=address,
        balance=u320_to_str(row['balance_lgb']),
        total_received=u320_to_str(row['total_received_lgb']),
        total_sent=u320_to_str(row['total_sent_lgb']),
        utxo_count=row['utxo_count'],
        tx_count=row['tx_count'],
        first_seen_height=row['first_seen_height'],
        last_seen_height=row['last_seen_height']
    )
    
    import json
    cache.setex(f"address:{address}", CACHE_TTL, json.dumps(result.model_dump()))
    
    return result


@app.get("/api/address/{address}/utxos", response_model=List[UTXO])
async def get_address_utxos(address: str, conn=Depends(get_db)):
    """Get unspent outputs for an address."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT o.txid, o.n as vout, o.amount_lgb, t.block_height
            FROM tx_outputs o
            JOIN txs t ON o.txid = t.txid
            WHERE o.address = %s AND o.spent_by_txid IS NULL
            ORDER BY t.block_height DESC
            LIMIT 1000
        """, (address,))
        rows = cur.fetchall()
    
    return [
        UTXO(
            txid=bytes_to_hex(r['txid']),
            vout=r['vout'],
            amount=u320_to_str(r['amount_lgb']),
            height=r['block_height']
        )
        for r in rows
    ]


@app.get("/api/search", response_model=SearchResult)
async def search(q: str = Query(..., min_length=1), conn=Depends(get_db)):
    """Search for block, transaction, or address."""
    q = q.strip()
    
    # Check if it's a height
    try:
        height = int(q)
        with conn.cursor() as cur:
            cur.execute("SELECT hash FROM blocks WHERE height = %s", (height,))
            row = cur.fetchone()
            if row:
                return SearchResult(type="block", value=str(height))
    except ValueError:
        pass
    
    # Check if it's a valid hex string (hash)
    if len(q) == 64:
        try:
            hash_bytes = bytes.fromhex(q)
            
            # Check blocks
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM blocks WHERE hash = %s", (hash_bytes,))
                if cur.fetchone():
                    return SearchResult(type="block", value=q)
            
            # Check transactions
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM txs WHERE txid = %s", (hash_bytes,))
                if cur.fetchone():
                    return SearchResult(type="transaction", value=q)
        except ValueError:
            pass
    
    # Check if it's an address
    if len(q) >= 25 and len(q) <= 36:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM address_stats WHERE address = %s", (q,))
            if cur.fetchone():
                return SearchResult(type="address", value=q)
        
        # Even if not in database, it might be a valid address
        # Return it as address and let the frontend validate
        return SearchResult(type="address", value=q)
    
    raise HTTPException(status_code=404, detail="Not found")


# ============================================================================
# Admin Endpoints
# ============================================================================

@app.post("/api/admin/reindex")
async def admin_reindex(
    start_height: int = 0,
    admin: bool = Depends(verify_admin),
    conn=Depends(get_db)
):
    """Trigger reindex from specified height (admin only)."""
    with conn.cursor() as cur:
        # Delete blocks from start_height onwards
        cur.execute("DELETE FROM blocks WHERE height >= %s", (start_height,))
        
        # Update chain state
        if start_height > 0:
            cur.execute("""
                SELECT hash, chainwork FROM blocks WHERE height = %s
            """, (start_height - 1,))
            row = cur.fetchone()
            if row:
                cur.execute("""
                    UPDATE chain_state 
                    SET best_tip_hash = %s, best_height = %s, best_chainwork = %s
                    WHERE id = 1
                """, (row[0], start_height - 1, row[1]))
        else:
            cur.execute("""
                UPDATE chain_state 
                SET best_height = -1, best_tip_hash = %s, best_chainwork = %s
                WHERE id = 1
            """, (bytes(32), bytes(32)))
        
        conn.commit()
    
    # Clear cache
    cache = get_cache()
    cache.flushdb()
    
    return {"status": "ok", "message": f"Reindex triggered from height {start_height}"}


@app.get("/api/admin/stats")
async def admin_stats(admin: bool = Depends(verify_admin), conn=Depends(get_db)):
    """Get indexer statistics (admin only)."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT COUNT(*) as count FROM blocks")
        blocks = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM txs")
        txs = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM address_stats")
        addresses = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) as count FROM reorg_log")
        reorgs = cur.fetchone()['count']
    
    return {
        "blocks": blocks,
        "transactions": txs,
        "addresses": addresses,
        "reorgs": reorgs
    }


# ============================================================================
# Run
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

