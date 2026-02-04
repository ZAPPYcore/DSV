# DSV Configuration Guide

## Node Configuration

### Command Line Options

```
dsvd [options]

Options:
  -d, --datadir=DIR       Data directory (default: ~/.dsv)
  -p, --port=PORT         P2P port (default: 8333)
  -r, --rpcport=PORT      RPC port (default: 8332)
  -a, --rpcauth=TOKEN     RPC auth token (required)
  -s, --seed=HOST:PORT    Seed node (can specify multiple)
  -n, --nolisten          Disable incoming P2P connections
  -m, --mempool=SIZE      Mempool size in MB (default: 300)
  -P, --prune=SIZE        Enable pruning, target size in MB
  --rpc-allow-remote      Allow remote RPC connections
  -h, --help              Show this help
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DSV_DATADIR` | Data directory | `~/.dsv` |
| `DSV_RPC_AUTH` | RPC authentication token | Required |
| `DSV_P2P_PORT` | P2P listen port | `8333` |
| `DSV_RPC_PORT` | RPC listen port | `8332` |

### Data Directory Structure

```
~/.dsv/
├── chainstate/          # LevelDB UTXO database
├── blocks/
│   ├── blk00000.dat    # Block data files
│   ├── blk00001.dat
│   └── ...
├── wallet.dat          # Wallet file (if using built-in wallet)
└── debug.log           # Log file
```

## Wallet Configuration

### Creating a Wallet

```bash
dsv-wallet create -w /path/to/wallet.dat
```

You will be prompted for 3 passphrases. Any 2 of these 3 are required to unlock the wallet.

### Wallet Options

```
dsv-wallet [options] <command>

Options:
  -w, --wallet=PATH   Wallet file (default: ~/.dsv/wallet.dat)
  -r, --rpc=URL       RPC endpoint (default: http://127.0.0.1:8332)
  -a, --auth=TOKEN    RPC auth token

Commands:
  create    Create a new wallet
  open      Open and verify wallet
  newaddr   Generate a new address
  listaddr  List all addresses
  export    Export mnemonic backup
```

## Explorer Configuration

### Indexer Environment

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dsv_explorer
DB_USER=dsv_explorer
DB_PASSWORD=secret

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Node RPC
RPC_URL=http://127.0.0.1:8332
RPC_AUTH=your_rpc_token

# Indexer
BATCH_SIZE=100
POLL_INTERVAL=1
REORG_DEPTH=100
METRICS_PORT=9100
```

### API Environment

```bash
# Database connection string
DB_DSN=host=localhost port=5432 dbname=dsv_explorer user=dsv_explorer password=secret

# Redis
REDIS_URL=redis://localhost:6379/0

# Admin
ADMIN_TOKEN=secret_admin_token

# Cache
CACHE_TTL=60
```

### Web UI Environment

```bash
# API endpoint
VITE_API_URL=/api
```

## Docker Configuration

### Required Environment Variables

Create a `.env` file:

```bash
# RPC authentication
RPC_AUTH=your_secret_rpc_token

# Database password
DB_PASSWORD=your_database_password

# Admin token for explorer API
ADMIN_TOKEN=your_admin_token
```

### Starting the Stack

```bash
docker-compose up -d
```

### Viewing Logs

```bash
docker-compose logs -f node
docker-compose logs -f explorer-indexer
```

## Network Configuration

### Mainnet Defaults

- P2P Port: 8333
- RPC Port: 8332
- Network Magic: `DSVB` (0x44535642)

### Firewall Rules

```bash
# Allow P2P connections
sudo ufw allow 8333/tcp

# Allow RPC (localhost only by default)
# Only open if needed:
# sudo ufw allow from 10.0.0.0/8 to any port 8332
```

## Security Configuration

### RPC Security

1. Always set a strong RPC auth token
2. Keep RPC on localhost unless absolutely necessary
3. If exposing RPC, use TLS and firewall rules

### Generate RPC Token

```bash
openssl rand -hex 32
```

### Wallet Security

1. Store the 3 passphrases in separate secure locations
2. Never store passphrases digitally
3. Test wallet recovery before storing funds

## Performance Tuning

### Node Tuning

```bash
# Increase mempool for high-traffic nodes
dsvd --mempool=1000

# Enable pruning for disk-constrained nodes
dsvd --prune=10000
```

### Database Tuning

PostgreSQL configuration for explorer:

```sql
-- postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 128MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 4
max_parallel_workers_per_gather = 2
max_parallel_workers = 4
```

