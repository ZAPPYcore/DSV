# DSV Block Explorer Architecture

## Overview

The DSV Block Explorer is a production-grade, reorg-safe blockchain indexing and query system. It is designed as a completely separate service from the DSV node to ensure security isolation and independent scalability.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Block Explorer Stack                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐  │
│  │  DSV Node   │    │   Indexer   │    │      PostgreSQL         │  │
│  │             │───▶│             │───▶│                         │  │
│  │   (RPC)     │    │  (Python)   │    │  blocks, txs, utxos     │  │
│  └─────────────┘    └─────────────┘    └───────────┬─────────────┘  │
│                                                     │                │
│                      ┌─────────────┐                │                │
│                      │    Redis    │◀───────────────┤                │
│                      │   (Cache)   │                │                │
│                      └──────┬──────┘                │                │
│                             │                       │                │
│                      ┌──────▼──────┐                │                │
│                      │  API Server │◀───────────────┘                │
│                      │  (FastAPI)  │                                 │
│                      └──────┬──────┘                                 │
│                             │                                        │
│                      ┌──────▼──────┐                                 │
│                      │   Web UI    │                                 │
│                      │   (React)   │                                 │
│                      └─────────────┘                                 │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Indexer (`explorer/indexer/`)

The indexer is a Python service that reads blockchain data from the DSV node and populates the PostgreSQL database.

#### Responsibilities
- Connect to DSV node via RPC
- Follow the best chain (highest chainwork)
- Parse blocks and transactions
- Handle chain reorganizations
- Batch writes for performance
- Crash recovery with checkpoints

#### Reorg Handling

The indexer maintains reorg safety through the following mechanism:

```python
def handle_reorg(self, new_tip_hash, new_tip_height):
    """Handle chain reorganization."""
    # 1. Find the fork point
    fork_point = self.find_fork_point(new_tip_hash)
    
    # 2. Rollback detached blocks
    detached = self.get_blocks_above(fork_point.height)
    for block in reversed(detached):
        self.rollback_block(block)
    
    # 3. Apply new blocks
    new_blocks = self.get_chain_to(new_tip_hash, fork_point.height)
    for block in new_blocks:
        self.index_block(block)
    
    # 4. Log the reorg
    self.log_reorg(detached, new_blocks)
```

#### Checkpointing

```python
class Checkpoint:
    """Crash-recovery checkpoint."""
    last_indexed_hash: str
    last_indexed_height: int
    timestamp: datetime
    
def save_checkpoint(self):
    """Atomic checkpoint save."""
    with self.db.transaction():
        self.db.execute("""
            UPDATE chain_state SET
                best_tip_hash = %s,
                best_height = %s,
                updated_at = NOW()
        """, (self.current_hash, self.current_height))
```

#### Configuration

```python
# explorer/indexer/config.py
NODE_RPC_URL = "http://localhost:8332"
NODE_RPC_USER = "dsv"
NODE_RPC_PASS = "from_env"

DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "dsv_explorer"
DB_USER = "dsv"
DB_PASS = "from_env"

BATCH_SIZE = 100  # Blocks per batch
CHECKPOINT_INTERVAL = 10  # Blocks between checkpoints
```

### 2. PostgreSQL Database

#### Schema Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Database Schema                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  chain_state (singleton)        blocks                               │
│  ├─ best_tip_hash              ├─ hash (PK)                         │
│  ├─ best_height                ├─ height (UNIQUE)                   │
│  ├─ best_chainwork             ├─ prev_hash                         │
│  └─ updated_at                 ├─ time, bits, nonce                 │
│                                ├─ merkle_root                       │
│                                ├─ chainwork                         │
│                                ├─ file_no, file_offset              │
│                                └─ tx_count                          │
│                                                                       │
│  txs                           tx_inputs                             │
│  ├─ txid (PK)                  ├─ txid (FK)                         │
│  ├─ block_hash (FK)            ├─ n (input index)                   │
│  ├─ block_height               ├─ prev_txid                         │
│  ├─ idx_in_block               ├─ prev_vout                         │
│  ├─ fee_lgb                    ├─ address                           │
│  ├─ size_bytes                 ├─ amount_lgb                        │
│  └─ created_at                 └─ is_coinbase                       │
│                                                                       │
│  tx_outputs                    address_stats                         │
│  ├─ txid (FK)                  ├─ address (PK)                      │
│  ├─ n (output index)           ├─ balance_lgb                       │
│  ├─ address                    ├─ total_received_lgb                │
│  ├─ amount_lgb                 ├─ total_sent_lgb                    │
│  ├─ spent_by_txid              ├─ utxo_count                        │
│  └─ spent_at_height            ├─ tx_count                          │
│                                └─ updated_at                        │
│                                                                       │
│  reorg_log                                                           │
│  ├─ id (PK)                                                         │
│  ├─ from_hash, to_hash                                              │
│  ├─ detached_range                                                  │
│  ├─ attached_range                                                  │
│  └─ at (timestamp)                                                  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### Key Indexes

```sql
-- Fast block lookups
CREATE UNIQUE INDEX idx_blocks_height ON blocks(height);
CREATE INDEX idx_blocks_prev ON blocks(prev_hash);

-- Fast transaction lookups
CREATE INDEX idx_txs_block ON txs(block_hash);
CREATE INDEX idx_txs_height ON txs(block_height);

-- Fast UTXO lookups
CREATE INDEX idx_tx_outputs_address ON tx_outputs(address);
CREATE INDEX idx_tx_outputs_unspent ON tx_outputs(address) 
    WHERE spent_by_txid IS NULL;

-- Fast input lookups
CREATE INDEX idx_tx_inputs_prev ON tx_inputs(prev_txid, prev_vout);
```

#### 320-bit Amount Storage

Amounts are stored as BYTEA(40):

```sql
-- Insert example
INSERT INTO tx_outputs (txid, n, address, amount_lgb)
VALUES ($1, $2, $3, $4::bytea);

-- Reading (convert to hex for display)
SELECT encode(amount_lgb, 'hex') as amount_hex FROM tx_outputs;
```

### 3. Redis Cache

Redis provides caching for frequently accessed data:

```python
CACHE_CONFIG = {
    'chain_info': {'ttl': 10},      # Chain state (short TTL)
    'block': {'ttl': 3600},          # Blocks (long TTL - immutable)
    'tx': {'ttl': 3600},             # Transactions (long TTL)
    'address': {'ttl': 60},          # Address stats (medium TTL)
    'latest_blocks': {'ttl': 10},    # Recent blocks list
    'search': {'ttl': 300},          # Search results
}
```

#### Cache Invalidation

```python
def invalidate_on_new_block(self, block_hash):
    """Invalidate caches when new block arrives."""
    self.redis.delete('chain_info')
    self.redis.delete('latest_blocks')
    
    # Don't invalidate individual block/tx caches
    # They're immutable once confirmed
    
def invalidate_on_reorg(self, detached_blocks):
    """Invalidate caches on reorg."""
    self.redis.flushdb()  # Nuclear option for reorgs
```

### 4. API Server (`explorer/api/`)

FastAPI-based REST API providing data to the Web UI.

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/chain` | Chain info (height, chainwork, etc.) |
| GET | `/api/blocks?limit=&cursor=` | Paginated block list |
| GET | `/api/block/:id` | Block by hash or height |
| GET | `/api/tx/:txid` | Transaction details |
| GET | `/api/address/:address` | Address info and history |
| GET | `/api/search?q=` | Search by hash/address/height |

#### Request/Response Flow

```
Client Request
      │
      ▼
┌─────────────┐
│   FastAPI   │
│   Router    │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│    Cache    │────▶│    Redis    │
│    Check    │     └─────────────┘
└──────┬──────┘
       │ Cache Miss
       ▼
┌─────────────┐     ┌─────────────┐
│   Database  │────▶│  PostgreSQL │
│    Query    │     └─────────────┘
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Response  │
│  Serialize  │
└──────┬──────┘
       │
       ▼
   JSON Response
```

#### Example Response: Block

```json
{
  "hash": "00000000ab12cd34...",
  "height": 12345,
  "prev_hash": "00000000ef56gh78...",
  "time": 1706745600,
  "bits": "1d00ffff",
  "nonce": 2083236893,
  "merkle_root": "4a5e1e4baab89f3a...",
  "chainwork": "0000000000000000000000000000000000000001234567890abcdef",
  "tx_count": 5,
  "txs": [
    {
      "txid": "abc123...",
      "fee": "0",
      "size": 250
    }
  ]
}
```

#### Rate Limiting

```python
from fastapi import Request
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.get("/api/blocks")
@limiter.limit("100/minute")
async def get_blocks(request: Request, limit: int = 10, cursor: str = None):
    ...
```

### 5. Web UI (`explorer/web/`)

React/TypeScript SPA with Tailwind CSS.

#### Component Structure

```
src/
├── main.tsx          # Entry point
├── App.tsx           # Root component with routing
├── api.ts            # API client
├── components/
│   ├── Layout.tsx    # Page layout wrapper
│   ├── SearchBar.tsx # Search functionality
│   ├── BlockList.tsx # Block list component
│   └── TxList.tsx    # Transaction list component
└── pages/
    ├── HomePage.tsx       # Latest blocks & txs
    ├── BlockPage.tsx      # Single block view
    ├── TransactionPage.tsx # Single tx view
    └── AddressPage.tsx    # Address history
```

#### State Management

Simple React state with SWR for data fetching:

```typescript
import useSWR from 'swr';

function BlockPage({ id }: { id: string }) {
  const { data, error, isLoading } = useSWR(
    `/api/block/${id}`,
    fetcher
  );
  
  if (isLoading) return <Skeleton />;
  if (error) return <Error message={error.message} />;
  
  return <BlockDetails block={data} />;
}
```

#### Responsive Design

```css
/* Mobile-first approach */
.block-list {
  @apply grid grid-cols-1 gap-4;
}

@screen md {
  .block-list {
    @apply grid-cols-2;
  }
}

@screen lg {
  .block-list {
    @apply grid-cols-3;
  }
}
```

## Data Flow

### New Block Flow

```
1. DSV Node receives block
   │
2. Indexer polls for new blocks (every 5s)
   │
3. Indexer fetches block via RPC
   │
4. Indexer parses and validates
   │
5. Indexer writes to PostgreSQL (batch)
   ├─ blocks table
   ├─ txs table
   ├─ tx_inputs table
   ├─ tx_outputs table
   └─ address_stats (updated)
   │
6. Redis cache invalidated
   │
7. API serves fresh data
   │
8. Web UI updates via polling/websocket
```

### Reorg Flow

```
1. Indexer detects chain tip changed
   │
2. Find fork point
   │
3. Begin database transaction
   │
4. For each detached block (newest first):
   │  ├─ Reverse UTXO changes
   │  ├─ Delete tx_inputs
   │  ├─ Delete tx_outputs
   │  ├─ Delete txs
   │  └─ Delete block
   │
5. For each new block (oldest first):
   │  └─ Normal indexing
   │
6. Log reorg to reorg_log
   │
7. Commit transaction
   │
8. Invalidate all caches
```

## Deployment

### Docker Compose

```yaml
services:
  explorer-db:
    image: postgres:15
    volumes:
      - explorer_db_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: dsv_explorer
      POSTGRES_USER: dsv
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    
  explorer-redis:
    image: redis:7-alpine
    
  explorer-indexer:
    build: ./explorer/indexer
    depends_on:
      - explorer-db
      - dsv-node
    environment:
      NODE_RPC_URL: http://dsv-node:8332
      DB_HOST: explorer-db
      
  explorer-api:
    build: ./explorer/api
    depends_on:
      - explorer-db
      - explorer-redis
    ports:
      - "8080:8080"
      
  explorer-web:
    build: ./explorer/web
    ports:
      - "80:80"
```

### Scaling Considerations

| Component | Horizontal Scaling | Notes |
|-----------|-------------------|-------|
| Indexer | No (single writer) | Use larger instance |
| PostgreSQL | Read replicas | Write to primary |
| Redis | Cluster mode | For high traffic |
| API | Yes (stateless) | Behind load balancer |
| Web | Yes (static) | CDN recommended |

## Monitoring

### Health Checks

```python
@app.get("/api/health")
async def health():
    checks = {
        "db": await check_db(),
        "redis": await check_redis(),
        "indexer_lag": await get_indexer_lag(),
    }
    
    healthy = all(c["status"] == "ok" for c in checks.values())
    return {
        "status": "healthy" if healthy else "degraded",
        "checks": checks
    }
```

### Metrics

Key metrics to monitor:
- Indexer lag (blocks behind node)
- API response times
- Cache hit rate
- Database connection pool usage
- Error rates by endpoint

### Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Indexer lag | > 5 blocks | > 20 blocks |
| API p99 latency | > 500ms | > 2000ms |
| Error rate | > 1% | > 5% |
| Cache hit rate | < 80% | < 50% |

## Security

### API Security
- Input validation on all parameters
- SQL injection prevention (parameterized queries)
- Rate limiting per IP
- CORS restricted to known origins

### Network Security
- PostgreSQL not exposed externally
- Redis not exposed externally
- API behind reverse proxy
- TLS termination at edge

### Data Security
- No private keys or sensitive data stored
- All data is public blockchain data
- Admin endpoints require authentication

