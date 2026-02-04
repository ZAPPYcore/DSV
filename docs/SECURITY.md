# DSV Security Guide

## Security Principles

1. **Defense in depth** - Multiple layers of security
2. **Least privilege** - Minimal access rights
3. **Secure defaults** - Safe out of the box
4. **No secrets in code** - Environment-based configuration

## Cryptographic Security

### Algorithms Used

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Signing | Ed25519 | libsodium |
| Hashing | SHA-256 (double) | libsodium |
| Address hashing | Blake2b-160 | libsodium |
| Key derivation | Argon2id | libsodium |
| Encryption | XSalsa20-Poly1305 | libsodium |
| Secret sharing | Shamir (GF(2^8)) | Custom |

### Why These Choices

- **Ed25519**: Fast, secure, compact signatures (64 bytes)
- **Double SHA-256**: Bitcoin-proven for PoW
- **Blake2b**: Faster than RIPEMD160, equally secure
- **Argon2id**: Best-in-class password hashing
- **libsodium**: Audited, widely-deployed crypto library

## Wallet Security

### TSA (Threshold Secret Sharing)

The wallet uses 2-of-3 Shamir Secret Sharing:

1. Master key is split into 3 shares
2. Each share is encrypted with a different passphrase
3. Any 2 passphrases can reconstruct the master key
4. Individual passphrases alone reveal nothing

### Key Storage

- Private keys are **never** stored in plaintext
- Seeds are encrypted with the master key
- Master key only exists in memory when unlocked
- All sensitive memory is securely zeroed after use

### Passphrase Requirements

- Minimum 8 characters
- Store each passphrase in a different location
- Consider using a passphrase manager
- Test recovery before storing funds

## Node Security

### RPC Security

1. **Localhost only** by default
2. **Auth token required** for all requests
3. **Request size limit** (1 MB default)
4. **Rate limiting** (100 req/sec default)
5. **Timeout protection** (30 sec default)

### Generating Secure Auth Token

```bash
openssl rand -hex 32
```

### Network Security

- P2P messages have checksums
- Invalid messages are rejected
- Peer misbehavior leads to disconnection
- No sensitive data in P2P protocol

## Code Security

### Memory Safety

- Bounds checking on all parsing
- Fixed-size buffers where possible
- Use of secure memory functions
- ASAN/UBSAN testing in CI

### Input Validation

All external input is validated:

- Block parsing
- Transaction parsing
- RPC input
- P2P messages
- Explorer API input

### Secure Coding Practices

```c
// Constant-time comparison
bool dsv_secure_compare(const void *a, const void *b, size_t len);

// Secure memory clearing
void dsv_secure_zero(void *ptr, size_t len);

// Bounds-checked parsing
bool dsv_read_u32(dsv_buffer_t *buf, uint32_t *v);
```

## Deployment Security

### Docker Security

```yaml
# Run as non-root user
USER dsv

# Read-only root filesystem
read_only: true

# Drop capabilities
cap_drop:
  - ALL

# No new privileges
security_opt:
  - no-new-privileges:true
```

### Systemd Security

```ini
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
```

### Network Security

```bash
# Firewall rules
ufw default deny incoming
ufw allow 8333/tcp  # P2P
# RPC should stay on localhost
```

### TLS for Production

For production deployments, use TLS:

```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/dsv.crt;
    ssl_certificate_key /etc/ssl/private/dsv.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}
```

## Secrets Management

### Never Commit Secrets

- Use `.env` files (gitignored)
- Use environment variables
- Use secret management systems for production

### Secret Rotation

1. Generate new secret
2. Update all services
3. Monitor for issues
4. Remove old secret

## Incident Response

### If RPC Token is Compromised

1. Stop node immediately
2. Generate new token
3. Restart with new token
4. Review logs for unauthorized access

### If Wallet is Compromised

1. Move funds to new wallet immediately
2. Create new wallet with new passphrases
3. Investigate how compromise occurred

### If Node is Compromised

1. Isolate the system
2. Preserve logs for analysis
3. Reinstall from known-good source
4. Restore data from backup
5. Rotate all credentials

## Security Checklist

### Before Production

- [ ] Strong RPC auth token generated
- [ ] Firewall configured
- [ ] TLS enabled (if exposing services)
- [ ] Backups configured and tested
- [ ] Monitoring in place
- [ ] Log rotation configured
- [ ] Services running as non-root
- [ ] Security updates scheduled

### Regular Maintenance

- [ ] Review security logs weekly
- [ ] Apply security updates promptly
- [ ] Rotate credentials quarterly
- [ ] Test backups monthly
- [ ] Review firewall rules quarterly
- [ ] Audit access logs monthly

## Reporting Security Issues

Please report security issues to: security@dsv.example.com

Do NOT report security issues in public GitHub issues.

We commit to:
- Acknowledge reports within 48 hours
- Provide regular updates on remediation
- Credit researchers (if desired) after fix

## Security Audit History

| Date | Auditor | Scope | Findings |
|------|---------|-------|----------|
| TBD | TBD | Full system | Pending |

Results will be published after remediation.

