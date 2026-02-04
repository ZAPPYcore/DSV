/**
 * DSV Cryptographic Operations Implementation
 * 
 * Uses libsodium for all cryptographic primitives.
 */

#include "dsv_crypto.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

/* Base58 alphabet (Bitcoin-compatible) */
static const char BASE58_ALPHABET[] = 
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Reverse lookup table for Base58 */
static const int8_t BASE58_MAP[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

int dsv_crypto_init(void) {
    if (sodium_init() < 0) {
        return DSV_ERR_CRYPTO;
    }
    return DSV_OK;
}

void dsv_sha256(dsv_hash256_t *out, const uint8_t *data, size_t len) {
    crypto_hash_sha256(out->data, data, len);
}

void dsv_hash256(dsv_hash256_t *out, const uint8_t *data, size_t len) {
    dsv_hash256_t first;
    crypto_hash_sha256(first.data, data, len);
    crypto_hash_sha256(out->data, first.data, sizeof(first.data));
    dsv_secure_zero(&first, sizeof(first));
}

void dsv_hash160(uint8_t out[20], const uint8_t *data, size_t len) {
    /*
     * Design decision: Using Blake2b-160 instead of RIPEMD160
     * 
     * libsodium does not provide RIPEMD160. Rather than adding another
     * dependency or implementing RIPEMD160 ourselves, we use Blake2b
     * truncated to 160 bits. Blake2b is:
     * - Faster than RIPEMD160
     * - Cryptographically stronger
     * - Already available in libsodium
     * 
     * This is documented in CRYPTO_NOTES.md
     */
    uint8_t sha256_out[32];
    crypto_hash_sha256(sha256_out, data, len);
    
    /* Blake2b with 20-byte output */
    crypto_generichash_blake2b(out, 20, sha256_out, 32, NULL, 0);
    
    dsv_secure_zero(sha256_out, sizeof(sha256_out));
}

bool dsv_hash_eq(const dsv_hash256_t *a, const dsv_hash256_t *b) {
    return sodium_memcmp(a->data, b->data, DSV_HASH_SIZE) == 0;
}

bool dsv_hash_is_zero(const dsv_hash256_t *h) {
    return sodium_is_zero(h->data, DSV_HASH_SIZE);
}

void dsv_hash_to_hex(char *hex, const dsv_hash256_t *h) {
    sodium_bin2hex(hex, 65, h->data, DSV_HASH_SIZE);
}

bool dsv_hash_from_hex(dsv_hash256_t *h, const char *hex) {
    size_t len = strlen(hex);
    if (len != 64) return false;
    
    size_t bin_len;
    return sodium_hex2bin(h->data, DSV_HASH_SIZE, hex, len, 
                          NULL, &bin_len, NULL) == 0 && bin_len == DSV_HASH_SIZE;
}

void dsv_hash_reverse(dsv_hash256_t *out, const dsv_hash256_t *in) {
    for (int i = 0; i < DSV_HASH_SIZE; i++) {
        out->data[i] = in->data[DSV_HASH_SIZE - 1 - i];
    }
}

void dsv_generate_seed(dsv_seed_t *seed) {
    randombytes_buf(seed->data, DSV_SEED_SIZE);
}

void dsv_keypair_from_seed(dsv_privkey_t *privkey, dsv_pubkey_t *pubkey,
                           const dsv_seed_t *seed) {
    crypto_sign_seed_keypair(pubkey->data, privkey->data, seed->data);
}

void dsv_pubkey_from_privkey(dsv_pubkey_t *pubkey, const dsv_privkey_t *privkey) {
    /* Ed25519 private key contains pubkey in last 32 bytes */
    memcpy(pubkey->data, privkey->data + 32, 32);
}

void dsv_sign(dsv_signature_t *sig, const uint8_t *msg, size_t msg_len,
              const dsv_privkey_t *privkey) {
    unsigned long long sig_len;
    crypto_sign_detached(sig->data, &sig_len, msg, msg_len, privkey->data);
}

bool dsv_verify(const dsv_signature_t *sig, const uint8_t *msg, size_t msg_len,
                const dsv_pubkey_t *pubkey) {
    return crypto_sign_verify_detached(sig->data, msg, msg_len, pubkey->data) == 0;
}

void dsv_address_from_pubkey(dsv_address_t *addr, const dsv_pubkey_t *pubkey,
                             uint8_t version) {
    addr->version = version;
    dsv_hash160(addr->hash, pubkey->data, DSV_PUBKEY_SIZE);
}

/* Internal: compute Base58Check checksum */
static void compute_checksum(uint8_t checksum[4], const uint8_t *data, size_t len) {
    dsv_hash256_t hash;
    dsv_hash256(&hash, data, len);
    memcpy(checksum, hash.data, 4);
    dsv_secure_zero(&hash, sizeof(hash));
}

void dsv_address_encode(char *str, size_t str_len, const dsv_address_t *addr) {
    /* Build payload: version (1) + hash (20) + checksum (4) = 25 bytes */
    uint8_t payload[25];
    payload[0] = addr->version;
    memcpy(payload + 1, addr->hash, 20);
    compute_checksum(payload + 21, payload, 21);
    
    /* Count leading zeros */
    int leading_zeros = 0;
    for (int i = 0; i < 25 && payload[i] == 0; i++) {
        leading_zeros++;
    }
    
    /* Convert to Base58 */
    char encoded[50];
    int encoded_len = 0;
    
    /* Process bytes */
    uint8_t temp[50];
    memcpy(temp, payload, 25);
    int temp_len = 25;
    
    while (temp_len > 0) {
        int carry = 0;
        int new_len = 0;
        
        for (int i = 0; i < temp_len; i++) {
            int value = carry * 256 + temp[i];
            carry = value % 58;
            int div = value / 58;
            if (new_len > 0 || div > 0) {
                temp[new_len++] = div;
            }
        }
        
        encoded[encoded_len++] = BASE58_ALPHABET[carry];
        temp_len = new_len;
    }
    
    /* Add leading '1's for each leading zero byte */
    for (int i = 0; i < leading_zeros; i++) {
        encoded[encoded_len++] = '1';
    }
    
    /* Reverse and copy to output */
    int out_len = 0;
    for (int i = encoded_len - 1; i >= 0 && out_len < (int)str_len - 1; i--) {
        str[out_len++] = encoded[i];
    }
    str[out_len] = '\0';
    
    dsv_secure_zero(payload, sizeof(payload));
    dsv_secure_zero(temp, sizeof(temp));
}

bool dsv_address_decode(dsv_address_t *addr, const char *str) {
    if (!str) return false;
    
    size_t len = strlen(str);
    if (len < 25 || len > 36) return false;
    
    /* Count leading '1's */
    int leading_ones = 0;
    for (size_t i = 0; i < len && str[i] == '1'; i++) {
        leading_ones++;
    }
    
    /* Decode Base58 */
    uint8_t decoded[50];
    memset(decoded, 0, sizeof(decoded));
    int decoded_len = 25;  /* Expected output length */
    
    for (size_t i = 0; i < len; i++) {
        int c = (unsigned char)str[i];
        if (c >= 128) return false;
        
        int digit = BASE58_MAP[c];
        if (digit < 0) return false;
        
        int carry = digit;
        for (int j = decoded_len - 1; j >= 0; j--) {
            carry += 58 * decoded[j];
            decoded[j] = carry % 256;
            carry /= 256;
        }
        
        if (carry != 0) return false;  /* Overflow */
    }
    
    /* Verify checksum */
    uint8_t expected_checksum[4];
    compute_checksum(expected_checksum, decoded, 21);
    
    if (!dsv_secure_compare(expected_checksum, decoded + 21, 4)) {
        dsv_secure_zero(decoded, sizeof(decoded));
        return false;
    }
    
    /* Extract address */
    addr->version = decoded[0];
    memcpy(addr->hash, decoded + 1, 20);
    
    dsv_secure_zero(decoded, sizeof(decoded));
    return true;
}

bool dsv_address_validate(const char *str) {
    dsv_address_t addr;
    bool valid = dsv_address_decode(&addr, str);
    dsv_secure_zero(&addr, sizeof(addr));
    return valid;
}

bool dsv_address_eq(const dsv_address_t *a, const dsv_address_t *b) {
    return a->version == b->version && 
           sodium_memcmp(a->hash, b->hash, 20) == 0;
}

void dsv_random_bytes(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
}

uint32_t dsv_random_u32(void) {
    return randombytes_random();
}

uint64_t dsv_random_u64(void) {
    uint64_t val;
    randombytes_buf(&val, sizeof(val));
    return val;
}

void dsv_secure_zero(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}

bool dsv_secure_compare(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

