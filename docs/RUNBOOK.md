# DSV Operations Runbook

## Quick Start

### Starting the Full Stack

```bash
# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps

# Check node status
docker-compose exec node dsv-cli --auth=$RPC_AUTH getblockchaininfo
```

### Stopping Services

```bash
# Graceful shutdown
docker-compose down

# With volume cleanup (DESTROYS DATA)
docker-compose down -v
```

## Common Operations

### Check Node Sync Status

```bash
dsv-cli --auth=$RPC_AUTH getblockchaininfo
```

Expected output:
```json
{
  "chain": "dsv",
  "blocks": 1234,
  "bestblockhash": "...",
  "chainwork": "..."
}
```

### Check Mempool

```bash
dsv-cli --auth=$RPC_AUTH getmempoolinfo
```

### View Node Logs

```bash
# Docker
docker-compose logs -f node

# Systemd
journalctl -u dsvd -f
```

### Check Explorer Status

```bash
curl http://localhost:8080/api/health
```

## Troubleshooting

### Node Won't Start

1. Check log files:
   ```bash
   tail -100 ~/.dsv/debug.log
   ```

2. Verify dependencies:
   ```bash
   ldd /usr/local/bin/dsvd
   ```

3. Check disk space:
   ```bash
   df -h ~/.dsv
   ```

4. Verify port availability:
   ```bash
   ss -tlnp | grep -E '8332|8333'
   ```

### Node Stuck Syncing

1. Check peer connections:
   ```bash
   dsv-cli --auth=$RPC_AUTH getpeerinfo
   ```

2. Restart node:
   ```bash
   systemctl restart dsvd
   ```

3. Check for network issues:
   ```bash
   ping seed-node.example.com
   ```

### Explorer Not Indexing

1. Check indexer logs:
   ```bash
   docker-compose logs -f explorer-indexer
   ```

2. Verify node connectivity:
   ```bash
   curl -X POST -H "Authorization: Bearer $RPC_AUTH" \
     -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
     http://localhost:8332
   ```

3. Check database connectivity:
   ```bash
   docker-compose exec explorer-db psql -U dsv_explorer -c "SELECT * FROM chain_state"
   ```

4. Restart indexer:
   ```bash
   docker-compose restart explorer-indexer
   ```

### Database Issues

1. Check database status:
   ```bash
   docker-compose exec explorer-db pg_isready
   ```

2. View database size:
   ```bash
   docker-compose exec explorer-db psql -U dsv_explorer -c "
     SELECT pg_size_pretty(pg_database_size('dsv_explorer'))
   "
   ```

3. Vacuum database:
   ```bash
   docker-compose exec explorer-db psql -U dsv_explorer -c "VACUUM ANALYZE"
   ```

### Cache Issues

1. Check Redis:
   ```bash
   docker-compose exec redis redis-cli ping
   ```

2. Clear cache:
   ```bash
   docker-compose exec redis redis-cli FLUSHALL
   ```

## Backup and Recovery

### Backup Node Data

```bash
# Stop node first
systemctl stop dsvd

# Backup chainstate
tar -czf chainstate-backup.tar.gz ~/.dsv/chainstate

# Backup blocks
tar -czf blocks-backup.tar.gz ~/.dsv/blocks

# Restart
systemctl start dsvd
```

### Backup Wallet

```bash
# The wallet file itself is encrypted
cp ~/.dsv/wallet.dat wallet-backup.dat

# Also securely store your 3 passphrases!
```

### Backup Explorer Database

```bash
docker-compose exec explorer-db pg_dump -U dsv_explorer dsv_explorer > explorer-backup.sql
```

### Restore Explorer Database

```bash
# Drop and recreate database
docker-compose exec explorer-db psql -U postgres -c "DROP DATABASE dsv_explorer"
docker-compose exec explorer-db psql -U postgres -c "CREATE DATABASE dsv_explorer OWNER dsv_explorer"

# Restore
cat explorer-backup.sql | docker-compose exec -T explorer-db psql -U dsv_explorer dsv_explorer
```

## Maintenance

### Rotating Logs

```bash
# Node logs are managed by systemd
journalctl --vacuum-time=30d

# Docker logs
docker-compose logs --tail=1000 > logs-$(date +%Y%m%d).txt
docker system prune -f
```

### Updating

```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d

# Or for native install:
systemctl stop dsvd
# Install new binaries
systemctl start dsvd
```

### Reindexing Explorer

```bash
# Via admin API
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/api/admin/reindex?start_height=0"

# Or reset database
docker-compose down
docker volume rm dsv_db-data
docker-compose up -d
```

## Monitoring

### Key Metrics

- Node block height vs network
- Mempool size
- Peer count
- Explorer indexer lag
- Database size
- API response times

### Health Checks

```bash
# Node RPC
curl -s http://localhost:8332 -d '{"method":"getblockcount"}' | jq .result

# Explorer API
curl -s http://localhost:8080/api/health | jq .

# Explorer Web
curl -s -o /dev/null -w "%{http_code}" http://localhost/
```

### Prometheus Metrics

- Indexer: `http://localhost:9100/metrics`
- API: (add endpoint for production)

## Emergency Procedures

### Chain Reorg Detected

1. Check reorg depth:
   ```sql
   SELECT * FROM reorg_log ORDER BY at DESC LIMIT 10;
   ```

2. If deep reorg (> 10 blocks), investigate cause

3. Monitor for continued reorgs

### Database Corruption

1. Stop services
2. Restore from backup
3. Reindex if needed

### Node Crash

1. Check logs for cause
2. Restart service
3. Monitor for repeated crashes
4. If data corruption, restore from backup

### Security Incident

1. Isolate affected systems
2. Rotate all credentials
3. Check for unauthorized access
4. Review logs
5. Notify stakeholders

