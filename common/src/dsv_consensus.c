/**
 * DSV Consensus Rules Implementation
 */

#include "dsv_consensus.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Genesis block parameters */
#define GENESIS_VERSION     1
#define GENESIS_TIMESTAMP   1738339200  /* 2025-02-01 00:00:00 UTC */
#define GENESIS_BITS        0x1d00ffff  /* Initial difficulty (Bitcoin-like) */
#define GENESIS_NONCE       0           /* To be mined */

/* Static genesis block and hash */
static dsv_block_t *genesis_block = NULL;
static dsv_hash256_t genesis_hash;
static bool genesis_computed = false;

/* Checkpoints - hardcoded for security */
static const dsv_checkpoint_t checkpoints[] = {
    /* Height 0 will be set dynamically from genesis hash */
    {0, {{0}}},
};
static const size_t checkpoint_count = sizeof(checkpoints) / sizeof(checkpoints[0]);

/* ==========================================================================
 * Block Reward Calculation
 * ========================================================================== */

void dsv_get_block_reward(dsv_u320_t *reward, int64_t height) {
    if (height < 0) {
        *reward = DSV_U320_ZERO;
        return;
    }
    
    /* Calculate halving epoch */
    int64_t halvings = height / DSV_HALVING_INTERVAL;
    
    /* After enough halvings, reward becomes 0 */
    if (halvings >= 320) {
        *reward = DSV_U320_ZERO;
        return;
    }
    
    /* Start with initial reward: 2.1 DSV */
    dsv_u320_copy(reward, &DSV_INITIAL_REWARD_LGB);
    
    /* Apply halvings by right-shifting */
    dsv_u320_shr(reward, reward, (unsigned int)halvings);
}

int64_t dsv_get_halving_epoch(int64_t height) {
    return height / DSV_HALVING_INTERVAL;
}

bool dsv_check_supply_limit(const dsv_u320_t *coinbase_amount, int64_t height) {
    /* 
     * This is a simplified check - in production we'd track cumulative supply.
     * For now, just verify coinbase doesn't exceed what's possible.
     */
    dsv_u320_t max_reward;
    dsv_get_block_reward(&max_reward, height);
    
    /* Add generous margin for fees */
    dsv_u320_t max_with_fees;
    dsv_u320_mul_u64(&max_with_fees, &max_reward, 2);
    
    return dsv_u320_cmp(coinbase_amount, &max_with_fees) <= 0;
}

/* ==========================================================================
 * Difficulty / Target
 * ========================================================================== */

void dsv_bits_to_target(uint8_t target[32], uint32_t bits) {
    memset(target, 0, 32);
    
    uint32_t mantissa = bits & 0x00FFFFFF;
    int exponent = (bits >> 24) & 0xFF;
    
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[31] = mantissa & 0xFF;
        target[30] = (mantissa >> 8) & 0xFF;
        target[29] = (mantissa >> 16) & 0xFF;
    } else {
        int byte_offset = 32 - exponent;
        if (byte_offset >= 0 && byte_offset < 30) {
            target[byte_offset + 2] = mantissa & 0xFF;
            target[byte_offset + 1] = (mantissa >> 8) & 0xFF;
            target[byte_offset] = (mantissa >> 16) & 0xFF;
        }
    }
}

uint32_t dsv_target_to_bits(const uint8_t target[32]) {
    /* Find first non-zero byte */
    int i;
    for (i = 0; i < 32 && target[i] == 0; i++);
    
    if (i == 32) return 0;
    
    uint32_t mantissa;
    int exponent = 32 - i;
    
    if (exponent >= 3) {
        mantissa = ((uint32_t)target[i] << 16) | 
                   ((uint32_t)target[i + 1] << 8) | 
                   (uint32_t)target[i + 2];
    } else {
        mantissa = (uint32_t)target[31] << (8 * (3 - exponent));
        exponent = 3;
    }
    
    /* Ensure mantissa doesn't have sign bit set */
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exponent++;
    }
    
    return ((uint32_t)exponent << 24) | mantissa;
}

bool dsv_hash_meets_target(const dsv_hash256_t *hash, uint32_t bits) {
    uint8_t target[32];
    dsv_bits_to_target(target, bits);
    
    /* Compare hash (in reverse byte order) with target */
    for (int i = 0; i < 32; i++) {
        if (hash->data[31 - i] < target[i]) return true;
        if (hash->data[31 - i] > target[i]) return false;
    }
    return true;  /* Equal is valid */
}

void dsv_get_work_from_bits(dsv_chainwork_t *work, uint32_t bits) {
    /*
     * Work = 2^256 / (target + 1)
     * For simplicity, we approximate: work ≈ 2^(256-exponent*8) / mantissa
     */
    memset(work->data, 0, 32);
    
    uint8_t target[32];
    dsv_bits_to_target(target, bits);
    
    /* Find the effective bit position of the target */
    int leading_zeros = 0;
    for (int i = 0; i < 32; i++) {
        if (target[i] == 0) {
            leading_zeros += 8;
        } else {
            uint8_t byte = target[i];
            while ((byte & 0x80) == 0) {
                leading_zeros++;
                byte <<= 1;
            }
            break;
        }
    }
    
    /* Work is approximately 2^leading_zeros */
    int byte_pos = 31 - (leading_zeros / 8);
    int bit_pos = leading_zeros % 8;
    
    if (byte_pos >= 0 && byte_pos < 32) {
        work->data[byte_pos] = 1 << bit_pos;
    }
}

void dsv_chainwork_add(dsv_chainwork_t *result,
                       const dsv_chainwork_t *a,
                       const dsv_chainwork_t *b) {
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t sum = (uint16_t)a->data[i] + b->data[i] + carry;
        result->data[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

int dsv_chainwork_cmp(const dsv_chainwork_t *a, const dsv_chainwork_t *b) {
    for (int i = 0; i < 32; i++) {
        if (a->data[i] > b->data[i]) return 1;
        if (a->data[i] < b->data[i]) return -1;
    }
    return 0;
}

uint32_t dsv_calculate_next_bits(uint32_t prev_bits,
                                  uint32_t first_block_time,
                                  uint32_t last_block_time) {
    /* Target timespan: 2016 blocks * 10 minutes = 2016000 seconds */
    const uint32_t target_timespan = DSV_RETARGET_INTERVAL * DSV_TARGET_SPACING;
    
    uint32_t actual_timespan = last_block_time - first_block_time;
    
    /* Clamp to 1/4 to 4x */
    if (actual_timespan < target_timespan / 4) {
        actual_timespan = target_timespan / 4;
    }
    if (actual_timespan > target_timespan * 4) {
        actual_timespan = target_timespan * 4;
    }
    
    /* Get current target */
    uint8_t target[32];
    dsv_bits_to_target(target, prev_bits);
    
    /* Multiply target by actual/target ratio */
    /* new_target = old_target * actual_timespan / target_timespan */
    
    /* Simple scaling - multiply then divide */
    uint64_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint64_t val = (uint64_t)target[i] * actual_timespan + carry;
        target[i] = 0;  /* Will be set after division */
        carry = val;
        
        /* Perform division as we go to avoid overflow */
        if (i < 31) {
            target[i + 1] = (uint8_t)(carry / target_timespan);
            carry = (carry % target_timespan) << 8;
        }
    }
    target[0] = (uint8_t)(carry / target_timespan);
    
    /* Convert back to bits */
    uint32_t new_bits = dsv_target_to_bits(target);
    
    /* Don't go below minimum difficulty */
    uint8_t pow_limit[32];
    dsv_bits_to_target(pow_limit, 0x1d00ffff);
    uint8_t new_target[32];
    dsv_bits_to_target(new_target, new_bits);
    
    for (int i = 0; i < 32; i++) {
        if (new_target[i] < pow_limit[i]) break;
        if (new_target[i] > pow_limit[i]) {
            new_bits = 0x1d00ffff;
            break;
        }
    }
    
    return new_bits;
}

/* ==========================================================================
 * Merkle Tree
 * ========================================================================== */

void dsv_compute_merkle_root(dsv_hash256_t *root,
                              const dsv_hash256_t *txids,
                              size_t tx_count) {
    if (tx_count == 0) {
        *root = DSV_HASH_ZERO;
        return;
    }
    
    if (tx_count == 1) {
        *root = txids[0];
        return;
    }
    
    /* Allocate working buffer */
    size_t level_size = tx_count;
    dsv_hash256_t *level = malloc(level_size * sizeof(dsv_hash256_t));
    if (!level) {
        *root = DSV_HASH_ZERO;
        return;
    }
    
    memcpy(level, txids, tx_count * sizeof(dsv_hash256_t));
    
    while (level_size > 1) {
        /* If odd number, duplicate last element */
        if (level_size % 2 == 1) {
            level[level_size] = level[level_size - 1];
            level_size++;
        }
        
        size_t new_size = level_size / 2;
        for (size_t i = 0; i < new_size; i++) {
            uint8_t combined[64];
            memcpy(combined, level[i * 2].data, 32);
            memcpy(combined + 32, level[i * 2 + 1].data, 32);
            dsv_hash256(&level[i], combined, 64);
        }
        level_size = new_size;
    }
    
    *root = level[0];
    free(level);
}

/* ==========================================================================
 * Transaction Validation
 * ========================================================================== */

int dsv_tx_check_basic(const dsv_tx_t *tx) {
    if (!tx) return DSV_ERR_INVALID;
    
    /* Check version */
    if (tx->version == 0 || tx->version > 2) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Must have at least one input and one output */
    if (tx->input_count == 0 || tx->output_count == 0) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Check limits */
    if (tx->input_count > DSV_MAX_INPUTS || tx->output_count > DSV_MAX_OUTPUTS) {
        return DSV_ERR_LIMIT;
    }
    
    /* Check for duplicate inputs */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        for (uint32_t j = i + 1; j < tx->input_count; j++) {
            if (dsv_hash_eq(&tx->inputs[i].prev_txid, &tx->inputs[j].prev_txid) &&
                tx->inputs[i].prev_vout == tx->inputs[j].prev_vout) {
                return DSV_ERR_DUPLICATE;
            }
        }
    }
    
    /* Check output amounts are valid (non-negative is guaranteed by type) */
    dsv_u320_t total_out = DSV_U320_ZERO;
    for (uint32_t i = 0; i < tx->output_count; i++) {
        /* Check for overflow when summing outputs */
        if (dsv_u320_add(&total_out, &total_out, &tx->outputs[i].amount)) {
            return DSV_ERR_OVERFLOW;
        }
        
        /* Check against max supply */
        if (dsv_u320_cmp(&total_out, &DSV_MAX_SUPPLY_LGB) > 0) {
            return DSV_ERR_CONSENSUS;
        }
    }
    
    return DSV_OK;
}

int dsv_tx_verify_signatures(const dsv_tx_t *tx) {
    if (dsv_tx_is_coinbase(tx)) {
        /* Coinbase has no signatures to verify */
        return DSV_OK;
    }
    
    /* Compute the signing hash */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        dsv_buffer_t *buf = dsv_buffer_new(1024);
        if (!buf) return DSV_ERR_NOMEM;
        
        dsv_tx_serialize_for_signing(buf, tx, i);
        
        dsv_hash256_t sighash;
        dsv_hash256(&sighash, buf->data, buf->pos);
        dsv_buffer_free(buf);
        
        /* Verify signature */
        if (!dsv_verify(&tx->inputs[i].signature,
                        sighash.data, DSV_HASH_SIZE,
                        &tx->inputs[i].pubkey)) {
            return DSV_ERR_VERIFY;
        }
    }
    
    return DSV_OK;
}

bool dsv_tx_is_coinbase(const dsv_tx_t *tx) {
    if (tx->input_count != 1) return false;
    
    /* Coinbase input has null prevout */
    return dsv_hash_is_zero(&tx->inputs[0].prev_txid) &&
           tx->inputs[0].prev_vout == 0xFFFFFFFF;
}

/* ==========================================================================
 * Block Validation
 * ========================================================================== */

int dsv_block_check_header(const dsv_block_header_t *header, uint32_t expected_bits) {
    if (!header) return DSV_ERR_INVALID;
    
    /* Check version */
    if (header->version == 0) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Check difficulty matches expected */
    if (header->bits != expected_bits) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Check proof of work */
    dsv_hash256_t hash;
    dsv_block_compute_hash(&hash, header);
    
    if (!dsv_hash_meets_target(&hash, header->bits)) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Check timestamp is not too far in the future (2 hours) */
    uint32_t now = (uint32_t)time(NULL);
    if (header->timestamp > now + 7200) {
        return DSV_ERR_CONSENSUS;
    }
    
    return DSV_OK;
}

int dsv_block_check_basic(const dsv_block_t *block) {
    if (!block) return DSV_ERR_INVALID;
    
    /* Must have at least coinbase */
    if (block->tx_count == 0) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* First transaction must be coinbase */
    if (!dsv_tx_is_coinbase(block->txs[0])) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* No other coinbase transactions */
    for (uint32_t i = 1; i < block->tx_count; i++) {
        if (dsv_tx_is_coinbase(block->txs[i])) {
            return DSV_ERR_CONSENSUS;
        }
    }
    
    /* Check each transaction */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        int err = dsv_tx_check_basic(block->txs[i]);
        if (err != DSV_OK) return err;
    }
    
    /* Verify merkle root */
    dsv_hash256_t *txids = malloc(block->tx_count * sizeof(dsv_hash256_t));
    if (!txids) return DSV_ERR_NOMEM;
    
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_tx_compute_txid(&txids[i], block->txs[i]);
    }
    
    dsv_hash256_t computed_root;
    dsv_compute_merkle_root(&computed_root, txids, block->tx_count);
    free(txids);
    
    if (!dsv_hash_eq(&computed_root, &block->header.merkle_root)) {
        return DSV_ERR_CONSENSUS;
    }
    
    return DSV_OK;
}

int dsv_block_check_coinbase(const dsv_block_t *block, int64_t height,
                              const dsv_u320_t *fees) {
    if (!block || block->tx_count == 0) return DSV_ERR_INVALID;
    
    dsv_tx_t *coinbase = block->txs[0];
    
    /* Calculate expected reward */
    dsv_u320_t reward;
    dsv_get_block_reward(&reward, height);
    
    /* Add fees */
    dsv_u320_t max_coinbase;
    if (dsv_u320_add(&max_coinbase, &reward, fees)) {
        return DSV_ERR_OVERFLOW;
    }
    
    /* Sum coinbase outputs */
    dsv_u320_t coinbase_total = DSV_U320_ZERO;
    for (uint32_t i = 0; i < coinbase->output_count; i++) {
        if (dsv_u320_add(&coinbase_total, &coinbase_total, &coinbase->outputs[i].amount)) {
            return DSV_ERR_OVERFLOW;
        }
    }
    
    /* Coinbase can't exceed reward + fees */
    if (dsv_u320_cmp(&coinbase_total, &max_coinbase) > 0) {
        return DSV_ERR_CONSENSUS;
    }
    
    return DSV_OK;
}

/* ==========================================================================
 * Genesis Block
 * ========================================================================== */

static void create_genesis_block(void) {
    if (genesis_block) return;
    
    genesis_block = dsv_block_new();
    if (!genesis_block) return;
    
    /* Header */
    genesis_block->header.version = GENESIS_VERSION;
    genesis_block->header.prev_hash = DSV_HASH_ZERO;
    genesis_block->header.timestamp = GENESIS_TIMESTAMP;
    genesis_block->header.bits = GENESIS_BITS;
    genesis_block->header.nonce = GENESIS_NONCE;
    
    /* Coinbase transaction */
    dsv_tx_t *coinbase = dsv_tx_new();
    if (!coinbase) {
        dsv_block_free(genesis_block);
        genesis_block = NULL;
        return;
    }
    
    coinbase->version = 1;
    coinbase->input_count = 1;
    coinbase->inputs = calloc(1, sizeof(dsv_txin_t));
    if (!coinbase->inputs) {
        dsv_tx_free(coinbase);
        dsv_block_free(genesis_block);
        genesis_block = NULL;
        return;
    }
    
    /* Null input for coinbase */
    coinbase->inputs[0].prev_txid = DSV_HASH_ZERO;
    coinbase->inputs[0].prev_vout = 0xFFFFFFFF;
    
    /* Genesis message in pubkey field */
    const char *msg = "DSV Genesis 2025-02-01 Dynamic Storage of Value";
    memcpy(coinbase->inputs[0].pubkey.data, msg, 
           DSV_MIN(strlen(msg), DSV_PUBKEY_SIZE));
    
    /* Output with genesis reward */
    coinbase->output_count = 1;
    coinbase->outputs = calloc(1, sizeof(dsv_txout_t));
    if (!coinbase->outputs) {
        dsv_tx_free(coinbase);
        dsv_block_free(genesis_block);
        genesis_block = NULL;
        return;
    }
    
    dsv_get_block_reward(&coinbase->outputs[0].amount, 0);
    coinbase->outputs[0].address.version = DSV_ADDR_VERSION_MAINNET;
    /* Genesis address - first 20 bytes of SHA256("DSV") */
    const char *genesis_addr_preimage = "DSV";
    dsv_hash160(coinbase->outputs[0].address.hash, 
                (const uint8_t *)genesis_addr_preimage,
                strlen(genesis_addr_preimage));
    
    dsv_block_add_tx(genesis_block, coinbase);
    
    /* Compute merkle root */
    dsv_hash256_t txid;
    dsv_tx_compute_txid(&txid, coinbase);
    dsv_compute_merkle_root(&genesis_block->header.merkle_root, &txid, 1);
    
    /* Compute block hash */
    dsv_block_compute_hash(&genesis_hash, &genesis_block->header);
    genesis_computed = true;
}

dsv_block_t *dsv_get_genesis_block(void) {
    if (!genesis_block) {
        create_genesis_block();
    }
    return genesis_block;
}

const dsv_hash256_t *dsv_get_genesis_hash(void) {
    if (!genesis_computed) {
        create_genesis_block();
    }
    return &genesis_hash;
}

/* ==========================================================================
 * Checkpoints
 * ========================================================================== */

const dsv_checkpoint_t *dsv_get_checkpoint(int64_t height) {
    for (size_t i = 0; i < checkpoint_count; i++) {
        if (checkpoints[i].height == height) {
            return &checkpoints[i];
        }
    }
    return NULL;
}

bool dsv_verify_checkpoint(int64_t height, const dsv_hash256_t *hash) {
    const dsv_checkpoint_t *cp = dsv_get_checkpoint(height);
    if (!cp) return true;  /* No checkpoint at this height */
    
    /* Height 0 uses dynamic genesis hash */
    if (height == 0) {
        return dsv_hash_eq(hash, dsv_get_genesis_hash());
    }
    
    return dsv_hash_eq(hash, &cp->hash);
}

