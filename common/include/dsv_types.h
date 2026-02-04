/**
 * DSV Core Types
 * 
 * Design decisions:
 * - 320-bit unsigned integer stored as 5×uint64 in little-endian order
 * - All amounts are in LGB (smallest unit): 1 DSV = 10^72 LGB
 * - Hash types are 32 bytes (SHA-256 output)
 */

#ifndef DSV_TYPES_H
#define DSV_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Constants
 * ========================================================================== */

#define DSV_HASH_SIZE           32
#define DSV_PUBKEY_SIZE         32   /* Ed25519 public key */
#define DSV_PRIVKEY_SIZE        64   /* Ed25519 secret key (seed + pubkey) */
#define DSV_SIGNATURE_SIZE      64   /* Ed25519 signature */
#define DSV_SEED_SIZE           32   /* Ed25519 seed */
#define DSV_ADDRESS_SIZE        25   /* 1 byte version + 20 byte hash + 4 byte checksum */
#define DSV_ADDRESS_STR_SIZE    36   /* Base58Check encoded address max length */

#define DSV_MAX_BLOCK_SIZE      1000000  /* 1 MB max block */
#define DSV_MAX_TX_SIZE         100000   /* 100 KB max tx */
#define DSV_MAX_INPUTS          1000
#define DSV_MAX_OUTPUTS         1000

#define DSV_COINBASE_MATURITY   100
#define DSV_HALVING_INTERVAL    216
#define DSV_RETARGET_INTERVAL   2016
#define DSV_TARGET_SPACING      600      /* 10 minutes in seconds */

#define DSV_MAX_SUPPLY_DSV      210000ULL
#define DSV_INITIAL_REWARD_DSV  21       /* 2.1 DSV = 21/10 */
#define DSV_REWARD_DIVISOR      10

/* Address version bytes */
#define DSV_ADDR_VERSION_MAINNET    0x00
#define DSV_ADDR_VERSION_TESTNET    0x6F

/* ==========================================================================
 * 320-bit Unsigned Integer (5×uint64 little-endian)
 * ========================================================================== */

/**
 * 320-bit unsigned integer for DSV amounts.
 * Stored as 5 uint64_t values in little-endian order.
 * parts[0] is the least significant 64 bits.
 */
typedef struct {
    uint64_t parts[5];
} dsv_u320_t;

/* Zero constant */
extern const dsv_u320_t DSV_U320_ZERO;

/* Maximum supply in LGB: 210,000 DSV × 10^72 */
extern const dsv_u320_t DSV_MAX_SUPPLY_LGB;

/* 1 DSV in LGB: 10^72 */
extern const dsv_u320_t DSV_ONE_DSV_LGB;

/* Initial block reward: 2.1 DSV in LGB */
extern const dsv_u320_t DSV_INITIAL_REWARD_LGB;

/* ==========================================================================
 * Hash Types
 * ========================================================================== */

typedef struct {
    uint8_t data[DSV_HASH_SIZE];
} dsv_hash256_t;

extern const dsv_hash256_t DSV_HASH_ZERO;

/* ==========================================================================
 * Key Types
 * ========================================================================== */

typedef struct {
    uint8_t data[DSV_PUBKEY_SIZE];
} dsv_pubkey_t;

typedef struct {
    uint8_t data[DSV_PRIVKEY_SIZE];
} dsv_privkey_t;

typedef struct {
    uint8_t data[DSV_SEED_SIZE];
} dsv_seed_t;

typedef struct {
    uint8_t data[DSV_SIGNATURE_SIZE];
} dsv_signature_t;

/* ==========================================================================
 * Address Type
 * ========================================================================== */

typedef struct {
    uint8_t version;
    uint8_t hash[20];  /* RIPEMD160(SHA256(pubkey)) */
} dsv_address_t;

/* ==========================================================================
 * Transaction Types
 * ========================================================================== */

/**
 * Transaction input - references a previous output.
 */
typedef struct {
    dsv_hash256_t prev_txid;    /* Previous transaction hash */
    uint32_t prev_vout;          /* Index of output in previous tx */
    dsv_pubkey_t pubkey;        /* Public key for verification */
    dsv_signature_t signature;   /* Signature over tx hash */
} dsv_txin_t;

/**
 * Transaction output - spendable value with owner.
 */
typedef struct {
    dsv_u320_t amount;           /* Amount in LGB */
    dsv_address_t address;       /* Recipient address */
} dsv_txout_t;

/**
 * Transaction structure.
 */
typedef struct {
    uint32_t version;            /* Transaction version */
    uint32_t input_count;
    dsv_txin_t *inputs;
    uint32_t output_count;
    dsv_txout_t *outputs;
    uint32_t locktime;           /* Block height or timestamp */
    
    /* Cached values (not serialized) */
    dsv_hash256_t txid;          /* Transaction ID (hash) */
    bool txid_computed;
} dsv_tx_t;

/**
 * Block header structure (80 bytes like Bitcoin).
 */
typedef struct {
    uint32_t version;
    dsv_hash256_t prev_hash;
    dsv_hash256_t merkle_root;
    uint32_t timestamp;
    uint32_t bits;               /* Compact difficulty target */
    uint32_t nonce;
} dsv_block_header_t;

#define DSV_BLOCK_HEADER_SIZE 80

/**
 * Block structure.
 */
typedef struct {
    dsv_block_header_t header;
    uint32_t tx_count;
    dsv_tx_t **txs;
    
    /* Cached values */
    dsv_hash256_t hash;
    bool hash_computed;
    uint64_t file_no;
    uint64_t file_offset;
} dsv_block_t;

/* ==========================================================================
 * Chain State Types
 * ========================================================================== */

/**
 * Chainwork - accumulated difficulty (256-bit).
 */
typedef struct {
    uint8_t data[32];
} dsv_chainwork_t;

/**
 * Block index entry - in-memory representation of block metadata.
 */
typedef struct dsv_block_index_s {
    dsv_hash256_t hash;
    dsv_hash256_t prev_hash;
    int64_t height;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    dsv_chainwork_t chainwork;
    
    uint64_t file_no;
    uint64_t file_offset;
    uint32_t tx_count;
    
    struct dsv_block_index_s *prev;  /* Link to previous block index */
    bool on_main_chain;
} dsv_block_index_t;

/**
 * UTXO entry.
 */
typedef struct {
    dsv_hash256_t txid;
    uint32_t vout;
    dsv_u320_t amount;
    dsv_address_t address;
    int64_t height;              /* Block height where created */
    bool is_coinbase;
} dsv_utxo_t;

/* ==========================================================================
 * Error Codes
 * ========================================================================== */

typedef enum {
    DSV_OK = 0,
    DSV_ERR_NOMEM = -1,
    DSV_ERR_INVALID = -2,
    DSV_ERR_OVERFLOW = -3,
    DSV_ERR_UNDERFLOW = -4,
    DSV_ERR_NOT_FOUND = -5,
    DSV_ERR_DUPLICATE = -6,
    DSV_ERR_IO = -7,
    DSV_ERR_CRYPTO = -8,
    DSV_ERR_PARSE = -9,
    DSV_ERR_VERIFY = -10,
    DSV_ERR_CONSENSUS = -11,
    DSV_ERR_DATABASE = -12,
    DSV_ERR_NETWORK = -13,
    DSV_ERR_RPC = -14,
    DSV_ERR_TIMEOUT = -15,
    DSV_ERR_LIMIT = -16,
    DSV_ERR_AUTH = -17,
} dsv_error_t;

/* ==========================================================================
 * Utility Macros
 * ========================================================================== */

#define DSV_MIN(a, b) ((a) < (b) ? (a) : (b))
#define DSV_MAX(a, b) ((a) > (b) ? (a) : (b))

#define DSV_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Secure memory clear */
#define DSV_SECURE_ZERO(ptr, size) do { \
    volatile uint8_t *_p = (volatile uint8_t *)(ptr); \
    size_t _s = (size); \
    while (_s--) *_p++ = 0; \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* DSV_TYPES_H */

