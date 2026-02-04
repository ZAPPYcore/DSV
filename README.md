# Dynamic Storage of Value (DSV)

A cryptocurrency implementation featuring a lightweight secure blockchain node, secure wallet with threshold secret sharing, and a full-featured block explorer.

## Overview

DSV is a UTXO-based cryptocurrency with:
- **Proof of Work**: Bitcoin-style double SHA-256
- **Maximum Supply**: 210,000 DSV
- **Block Reward**: 2.1 DSV (halving every 216 blocks)
- **Smallest Unit**: LGB (1 DSV = 10^72 LGB)
- **Signatures**: Ed25519 (via libsodium)

## Components

### Node (`dsvd`)
Lightweight blockchain node with:
- RocksDB-backed UTXO storage
- Append-only block files
- P2P networking
- JSON-RPC API
- Mempool management

### Wallet (`dsv-wallet`)
Secure wallet featuring:
- TSA (2-of-3 threshold secret sharing) for key protection
- No plaintext key storage
- Base58Check address encoding
- Deterministic coin selection

### Block Explorer
Production-grade explorer with:
- PostgreSQL database
- Redis caching
- Reorg-safe indexing
- FastAPI REST API
- React/TypeScript Web UI

## Quick Start

### Using Docker Compose

```bash
# Start the entire stack
docker-compose up -d

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

The explorer will be available at http://localhost:80

### Building from Source

#### Prerequisites

- CMake 3.16+
- GCC or Clang with C11 support
- libsodium 1.0.18+
- RocksDB 6.0+
- libuv 1.0+
- cJSON

#### Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### Run Node

```bash
# Initialize data directory
./dsvd --datadir=/path/to/data --init

# Start node
./dsvd --datadir=/path/to/data
```

#### Run Wallet

```bash
# Create new wallet (will prompt for 3 passphrases)
./dsv-wallet create --wallet=/path/to/wallet

# Unlock wallet (requires 2 of 3 passphrases)
./dsv-wallet unlock --wallet=/path/to/wallet

# Generate new address
./dsv-wallet newaddress

# Send transaction
./dsv-wallet send --to=ADDRESS --amount=1.5
```

## Configuration

See [docs/CONFIG.md](docs/CONFIG.md) for detailed configuration options.

### Node Configuration

```ini
# dsv.conf
rpcport=8332
rpcuser=dsv
rpcpassword=your_secure_password
rpcallowip=127.0.0.1

p2pport=8333
maxconnections=125

datadir=/var/lib/dsv
prunemode=0
```

### Explorer Configuration

Environment variables:
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dsv_explorer
DB_USER=dsv
DB_PASSWORD=secure_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Node RPC
NODE_RPC_URL=http://localhost:8332
NODE_RPC_USER=dsv
NODE_RPC_PASSWORD=your_secure_password
```

## API Reference

### Node RPC

| Method | Description |
|--------|-------------|
| `getblockcount` | Get current block height |
| `getbestblockhash` | Get tip block hash |
| `getblock` | Get block by hash |
| `getblockhash` | Get block hash by height |
| `getrawtransaction` | Get transaction by txid |
| `sendrawtransaction` | Broadcast transaction |
| `getmempool` | Get mempool transactions |

### Explorer API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/chain` | Chain info |
| `GET /api/blocks` | List blocks |
| `GET /api/block/:id` | Get block |
| `GET /api/tx/:txid` | Get transaction |
| `GET /api/address/:addr` | Get address info |
| `GET /api/search?q=` | Search |

## Security

- All cryptography via libsodium
- Constant-time operations for sensitive data
- Memory zeroing after use
- No secrets in logs
- ASAN/UBSAN tested

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for details.

## Testing

```bash
# Run all tests
./scripts/run_tests.sh --all

# Run unit tests only
./scripts/run_tests.sh --unit

# Run with sanitizers
./scripts/run_tests.sh --asan --ubsan

# Run fuzz tests
./scripts/run_tests.sh --fuzz
```

## Documentation

- [CONFIG.md](docs/CONFIG.md) - Configuration reference
- [RUNBOOK.md](docs/RUNBOOK.md) - Operations guide
- [SECURITY.md](docs/SECURITY.md) - Security practices
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) - Threat analysis
- [CRYPTO_NOTES.md](docs/CRYPTO_NOTES.md) - Cryptographic design
- [EXPLORER_ARCHITECTURE.md](docs/EXPLORER_ARCHITECTURE.md) - Explorer design
- [AUDIT_CHECKLIST.md](docs/AUDIT_CHECKLIST.md) - Security audit checklist
- [RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) - Release process

## Project Structure

```
.
├── common/              # Shared libraries
│   ├── include/         # Headers
│   └── src/             # Implementation
├── node/                # Blockchain node
│   ├── include/
│   └── src/
├── wallet/              # Secure wallet
│   ├── include/
│   └── src/
├── cli/                 # Command-line interface
├── explorer/            # Block explorer
│   ├── indexer/         # Blockchain indexer
│   ├── api/             # REST API
│   └── web/             # Web UI
├── docker/              # Docker configurations
├── deploy/              # Deployment configs
│   └── systemd/         # Systemd services
├── tests/               # Test suites
│   ├── unit/
│   ├── integration/
│   └── fuzz/
├── docs/                # Documentation
└── scripts/             # Build and utility scripts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests and linters
4. Submit a pull request

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- libsodium for cryptographic primitives
- RocksDB for storage
- FastAPI for the API framework
- React for the web UI

