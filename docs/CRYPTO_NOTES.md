# DSV Cryptographic Notes

## Design Decisions

### 320-bit Amounts

DSV uses 320-bit unsigned integers for all amounts:
- 1 DSV = 10^72 LGB (smallest unit)
- Stored as 5×uint64 in little-endian order
- Provides massive precision headroom

```c
typedef struct {
    uint64_t parts[5];
} dsv_u320_t;
```

**Rationale**: The extreme precision allows for:
- Future subdivisions without protocol changes
- Avoiding floating-point in all calculations
- Simple serialization (40 bytes)

### Ed25519 Signing

We use Ed25519 instead of secp256k1 (Bitcoin's choice):

| Property | Ed25519 | secp256k1 |
|----------|---------|-----------|
| Signature size | 64 bytes | 70-72 bytes |
| Public key | 32 bytes | 33 bytes |
| Speed | ~5x faster | Baseline |
| Security level | ~128 bits | ~128 bits |
| Malleability | None | Requires extra checks |

**Rationale**: Smaller, faster, safer by default.

### Blake2b-160 for Address Hashing

Bitcoin uses RIPEMD160(SHA256(pubkey)) for addresses. We use Blake2b-160:

```c
void dsv_hash160(uint8_t out[20], const uint8_t *data, size_t len) {
    uint8_t sha256_out[32];
    crypto_hash_sha256(sha256_out, data, len);
    crypto_generichash_blake2b(out, 20, sha256_out, 32, NULL, 0);
}
```

**Rationale**:
- libsodium doesn't include RIPEMD160
- Blake2b is cryptographically stronger
- Blake2b is faster
- 160 bits provides adequate collision resistance

### Double SHA-256 for PoW

Block hashing uses Bitcoin-style double SHA-256:

```c
void dsv_hash256(dsv_hash256_t *out, const uint8_t *data, size_t len) {
    dsv_hash256_t first;
    crypto_hash_sha256(first.data, data, len);
    crypto_hash_sha256(out->data, first.data, 32);
}
```

**Rationale**: Proven secure in Bitcoin for 15+ years.

### Argon2id Key Derivation

Wallet passphrase → key derivation uses Argon2id:

```c
crypto_pwhash(key, 32, passphrase, strlen(passphrase),
              salt, 
              crypto_pwhash_OPSLIMIT_MODERATE,
              crypto_pwhash_MEMLIMIT_MODERATE,
              crypto_pwhash_ALG_ARGON2ID13);
```

Parameters:
- OPSLIMIT_MODERATE: 3 iterations
- MEMLIMIT_MODERATE: 256 MB
- Salt: 16 bytes random

**Rationale**: Best-in-class password hashing, resistant to both GPU and ASIC attacks.

## Shamir's Secret Sharing

### Implementation

We implement 2-of-3 Shamir's Secret Sharing over GF(2^8):

```c
// Field: GF(2^8) with polynomial 0x11D (AES polynomial)
// Threshold: k=2
// Shares: n=3

void dsv_tsa_split(const uint8_t secret[32], dsv_share_t shares[3]) {
    // For each byte i of the 32-byte secret:
    // Generate random coefficient a[i]
    // Share j value = secret[i] + a[i] * j (in GF(2^8))
}
```

### Reconstruction

```c
bool dsv_tsa_combine(uint8_t secret[32], 
                     const dsv_share_t *share1,
                     const dsv_share_t *share2) {
    // Lagrange interpolation at x=0
    // L1(0) = x2 / (x2 - x1) in GF(2^8)
    // L2(0) = x1 / (x1 - x2) in GF(2^8)
    // secret[i] = share1[i] * L1(0) + share2[i] * L2(0)
}
```

### Security Properties

- Any 1 share reveals **nothing** about the secret
- Any 2 shares perfectly reconstruct the secret
- The scheme is information-theoretically secure

## Constant-Time Operations

### Comparison

```c
bool dsv_secure_compare(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}
```

### Memory Zeroing

```c
void dsv_secure_zero(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}
```

**Rationale**: Prevent timing side-channels in security-critical operations.

## Address Encoding

### Base58Check

Addresses use Base58Check encoding (Bitcoin-compatible):

1. Version byte (0x00 for mainnet)
2. 20-byte hash160 of public key
3. 4-byte checksum (first 4 bytes of double-SHA256)
4. Base58 encode the 25 bytes

```
Address = Base58(version || hash160 || checksum)
```

### Format

- Mainnet addresses start with '1'
- Total length: 25-34 characters

## Random Number Generation

All randomness comes from libsodium's CSPRNG:

```c
void dsv_random_bytes(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
}
```

**Rationale**: Uses OS entropy sources, cryptographically secure.

## Proof of Work

### Target Representation

Difficulty target uses Bitcoin's compact "bits" format:

```
bits = (exponent << 24) | mantissa
target = mantissa * 2^(8*(exponent-3))
```

### Validation

```c
bool dsv_hash_meets_target(const dsv_hash256_t *hash, uint32_t bits) {
    uint8_t target[32];
    dsv_bits_to_target(target, bits);
    
    // Compare hash (reversed) with target
    for (int i = 0; i < 32; i++) {
        if (hash->data[31-i] < target[i]) return true;
        if (hash->data[31-i] > target[i]) return false;
    }
    return true;
}
```

## Transaction Signing

### Signature Hash

```c
// For each input:
// 1. Serialize tx with empty signatures for other inputs
// 2. Hash with double SHA-256
// 3. Sign the hash with Ed25519
```

### Verification

```c
bool dsv_verify(const dsv_signature_t *sig,
                const uint8_t *msg, size_t msg_len,
                const dsv_pubkey_t *pubkey) {
    return crypto_sign_verify_detached(
        sig->data, msg, msg_len, pubkey->data) == 0;
}
```

## Security Margin

| Primitive | Security Level | Our Usage | Margin |
|-----------|---------------|-----------|--------|
| SHA-256 | 128-bit | Double hashing | Good |
| Ed25519 | ~128-bit | Signing | Good |
| Blake2b-160 | 80-bit collision | Address hashing | Adequate |
| Argon2id | Configurable | Key derivation | Good |
| XSalsa20-Poly1305 | 256-bit | Encryption | Excellent |

## Known Limitations

1. **Blake2b-160 collision resistance**: 80 bits is lower than SHA256. However, for address generation, this is sufficient as an attacker would need to generate a key pair that hashes to a target address.

2. **No quantum resistance**: Ed25519 and SHA-256 are vulnerable to quantum computers. Migration path: Protocol upgrade when quantum computers become practical.

3. **Deterministic signatures**: Ed25519 signatures are deterministic from the message and key. This is a feature (prevents nonce reuse attacks) but means identical messages produce identical signatures.

## References

1. Bernstein, D.J. et al. "Ed25519: high-speed high-security signatures"
2. Aumasson, J.P. et al. "BLAKE2: simpler, smaller, fast as MD5"
3. Biryukov, A. et al. "Argon2: the memory-hard function"
4. Shamir, A. "How to share a secret"

