/**
 * DSV Cryptographic Operations
 * 
 * Uses libsodium exclusively for all cryptographic operations.
 * Ed25519 for signing, SHA-256 for hashing.
 */

#ifndef DSV_CRYPTO_H
#define DSV_CRYPTO_H

#include "dsv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Initialization
 * ========================================================================== */

/**
 * Initialize cryptographic subsystem.
 * Must be called before any other crypto function.
 * Returns DSV_OK on success.
 */
int dsv_crypto_init(void);

/* ==========================================================================
 * Hashing
 * ========================================================================== */

/**
 * Compute SHA-256 hash.
 */
void dsv_sha256(dsv_hash256_t *out, const uint8_t *data, size_t len);

/**
 * Compute double SHA-256 (SHA256(SHA256(data))) - used for PoW and tx hashing.
 */
void dsv_hash256(dsv_hash256_t *out, const uint8_t *data, size_t len);

/**
 * Compute RIPEMD160(SHA256(data)) - used for addresses.
 * Note: libsodium doesn't have RIPEMD160, using Blake2b-160 as secure alternative.
 * This is a design choice documented in CRYPTO_NOTES.md.
 */
void dsv_hash160(uint8_t out[20], const uint8_t *data, size_t len);

/**
 * Compare two hashes (constant-time).
 */
bool dsv_hash_eq(const dsv_hash256_t *a, const dsv_hash256_t *b);

/**
 * Check if hash is zero.
 */
bool dsv_hash_is_zero(const dsv_hash256_t *h);

/**
 * Convert hash to hex string (65 bytes including null terminator).
 */
void dsv_hash_to_hex(char *hex, const dsv_hash256_t *h);

/**
 * Parse hash from hex string.
 */
bool dsv_hash_from_hex(dsv_hash256_t *h, const char *hex);

/**
 * Reverse hash bytes (for display, Bitcoin convention).
 */
void dsv_hash_reverse(dsv_hash256_t *out, const dsv_hash256_t *in);

/* ==========================================================================
 * Key Generation and Signing
 * ========================================================================== */

/**
 * Generate random seed.
 */
void dsv_generate_seed(dsv_seed_t *seed);

/**
 * Derive keypair from seed.
 */
void dsv_keypair_from_seed(dsv_privkey_t *privkey, dsv_pubkey_t *pubkey, 
                           const dsv_seed_t *seed);

/**
 * Extract public key from private key.
 */
void dsv_pubkey_from_privkey(dsv_pubkey_t *pubkey, const dsv_privkey_t *privkey);

/**
 * Sign a message.
 */
void dsv_sign(dsv_signature_t *sig, const uint8_t *msg, size_t msg_len,
              const dsv_privkey_t *privkey);

/**
 * Verify a signature.
 */
bool dsv_verify(const dsv_signature_t *sig, const uint8_t *msg, size_t msg_len,
                const dsv_pubkey_t *pubkey);

/* ==========================================================================
 * Address Operations
 * ========================================================================== */

/**
 * Compute address from public key.
 */
void dsv_address_from_pubkey(dsv_address_t *addr, const dsv_pubkey_t *pubkey,
                             uint8_t version);

/**
 * Encode address to Base58Check string.
 */
void dsv_address_encode(char *str, size_t str_len, const dsv_address_t *addr);

/**
 * Decode address from Base58Check string.
 */
bool dsv_address_decode(dsv_address_t *addr, const char *str);

/**
 * Validate address checksum.
 */
bool dsv_address_validate(const char *str);

/**
 * Compare addresses.
 */
bool dsv_address_eq(const dsv_address_t *a, const dsv_address_t *b);

/* ==========================================================================
 * Random Numbers
 * ========================================================================== */

/**
 * Fill buffer with random bytes.
 */
void dsv_random_bytes(uint8_t *buf, size_t len);

/**
 * Generate random uint32.
 */
uint32_t dsv_random_u32(void);

/**
 * Generate random uint64.
 */
uint64_t dsv_random_u64(void);

/* ==========================================================================
 * Secure Memory
 * ========================================================================== */

/**
 * Securely zero memory.
 */
void dsv_secure_zero(void *ptr, size_t len);

/**
 * Constant-time memory comparison.
 */
bool dsv_secure_compare(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DSV_CRYPTO_H */

