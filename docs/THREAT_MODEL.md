# DSV Threat Model

## System Overview

DSV consists of:
1. **Node**: Blockchain consensus, P2P networking, RPC API
2. **Wallet**: Key management, transaction signing
3. **Explorer**: Blockchain indexing, web interface

## Assets

### Critical Assets
- Private keys (wallet seeds)
- UTXO database integrity
- Blockchain data integrity
- User funds

### Important Assets
- RPC authentication tokens
- Database credentials
- TLS certificates
- Admin tokens

### Other Assets
- Availability of services
- User privacy (addresses, balances)
- Node IP addresses

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐              │
│  │  Node   │  │ Wallet  │  │   Indexer   │              │
│  └────┬────┘  └────┬────┘  └──────┬──────┘              │
│       │            │              │                      │
│  ┌────┴────────────┴──────────────┴─────┐               │
│  │         Internal Network             │               │
│  └───────────────────┬──────────────────┘               │
│                      │                                   │
└──────────────────────┼───────────────────────────────────┘
                       │
         ══════════════╪══════════════ Trust Boundary
                       │
┌──────────────────────┼───────────────────────────────────┐
│     UNTRUSTED ZONE   │                                   │
│  ┌─────────┐    ┌────┴────┐    ┌─────────────┐          │
│  │  P2P    │    │   RPC   │    │  Explorer   │          │
│  │ Peers   │    │ Clients │    │    Users    │          │
│  └─────────┘    └─────────┘    └─────────────┘          │
└─────────────────────────────────────────────────────────┘
```

## Threat Categories

### 1. Network Attacks

#### 1.1 Eclipse Attack
**Threat**: Attacker controls all peer connections
**Impact**: Double-spend, transaction censorship
**Mitigations**:
- Diverse peer selection
- Seed nodes from multiple sources
- Monitor peer diversity

#### 1.2 Sybil Attack
**Threat**: Attacker floods network with malicious nodes
**Impact**: Network disruption, eclipse attack enablement
**Mitigations**:
- Connection limits per IP range
- Reputation-based peer selection
- Proof-of-work for peer discovery

#### 1.3 DDoS Attack
**Threat**: Overwhelming node with requests
**Impact**: Service unavailability
**Mitigations**:
- Rate limiting
- Request size limits
- Connection limits

### 2. Consensus Attacks

#### 2.1 51% Attack
**Threat**: Attacker controls majority hash power
**Impact**: Double-spending, chain reorganization
**Mitigations**:
- Checkpoint system
- Reorg depth monitoring
- Confirmations for high-value transactions

#### 2.2 Selfish Mining
**Threat**: Attacker withholds blocks strategically
**Impact**: Unfair mining advantage
**Mitigations**:
- Fast block propagation
- Network monitoring

### 3. Application Attacks

#### 3.1 Buffer Overflow
**Threat**: Malformed input causes memory corruption
**Impact**: Code execution, crash
**Mitigations**:
- Bounds checking on all input
- ASAN/UBSAN testing
- Fuzz testing

#### 3.2 Integer Overflow
**Threat**: Arithmetic overflow in amount handling
**Impact**: Fund creation, double-spend
**Mitigations**:
- 320-bit integers with overflow checks
- Explicit overflow handling
- Unit tests for edge cases

#### 3.3 Signature Malleability
**Threat**: Modified signatures validate for same message
**Impact**: Transaction confusion
**Mitigations**:
- Ed25519 signatures are non-malleable
- Strict signature verification

### 4. Cryptographic Attacks

#### 4.1 Key Extraction
**Threat**: Private keys extracted from memory
**Impact**: Fund theft
**Mitigations**:
- Secure memory zeroing
- TSA key protection
- Memory encryption (OS-level)

#### 4.2 Side-Channel Attack
**Threat**: Timing/power analysis reveals keys
**Impact**: Key extraction
**Mitigations**:
- Constant-time comparisons
- libsodium implementations

#### 4.3 Weak Random Numbers
**Threat**: Predictable key generation
**Impact**: Key compromise
**Mitigations**:
- libsodium CSPRNG
- OS entropy sources

### 5. API Attacks

#### 5.1 Authentication Bypass
**Threat**: Accessing RPC without credentials
**Impact**: Unauthorized operations
**Mitigations**:
- Required auth token
- Constant-time token comparison

#### 5.2 Injection Attacks
**Threat**: Malicious input in API parameters
**Impact**: Data corruption, command execution
**Mitigations**:
- Parameterized queries
- Input validation
- Type checking

#### 5.3 Rate Limit Bypass
**Threat**: Circumventing rate limits
**Impact**: Resource exhaustion
**Mitigations**:
- Per-IP rate limiting
- Global rate limiting
- Exponential backoff

### 6. Physical Attacks

#### 6.1 Hardware Theft
**Threat**: Server/laptop stolen
**Impact**: Key exposure
**Mitigations**:
- Disk encryption
- TSA wallet protection
- Remote wipe capability

#### 6.2 Cold Boot Attack
**Threat**: Memory extraction from powered-off system
**Impact**: Key exposure
**Mitigations**:
- Memory encryption
- Secure memory clearing

## Risk Matrix

| Threat | Likelihood | Impact | Risk | Status |
|--------|------------|--------|------|--------|
| Eclipse Attack | Medium | High | High | Mitigated |
| 51% Attack | Low | Critical | Medium | Monitored |
| Buffer Overflow | Low | Critical | Medium | Mitigated |
| Key Extraction | Low | Critical | Medium | Mitigated |
| DDoS | High | Medium | High | Mitigated |
| API Injection | Medium | High | High | Mitigated |

## Security Assumptions

1. libsodium implementations are correct
2. OS random number generator is secure
3. Hardware is not compromised
4. At least 2 of 3 wallet passphrases remain secret
5. RPC token remains secret
6. Network has sufficient honest hash power

## Residual Risks

1. **51% attack**: Inherent to PoW systems
2. **Zero-day vulnerabilities**: Unknown bugs
3. **Social engineering**: Human factors
4. **Supply chain attacks**: Dependency compromise

## Security Monitoring

### Indicators of Compromise

- Unusual reorg depth (> 6 blocks)
- Unexpected peer connections
- Failed authentication attempts
- Unusual RPC patterns
- Memory anomalies

### Log Analysis

```bash
# Watch for auth failures
grep "Invalid auth" /var/log/dsv/debug.log

# Watch for reorgs
grep "REORGANIZE" /var/log/dsv/debug.log

# Watch for peer bans
grep "banned" /var/log/dsv/debug.log
```

## Incident Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| Critical | Active fund theft | Immediate |
| High | Vulnerability discovered | 24 hours |
| Medium | Suspicious activity | 48 hours |
| Low | Configuration issue | 1 week |

