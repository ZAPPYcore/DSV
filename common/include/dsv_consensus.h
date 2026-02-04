/**
 * DSV Consensus Rules
 * 
 * Hardcoded consensus parameters and validation rules.
 */

#ifndef DSV_CONSENSUS_H
#define DSV_CONSENSUS_H

#include "dsv_types.h"
#include "dsv_u320.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Block Reward Calculation
 * ========================================================================== */

/**
 * Calculate block reward for given height.
 * Initial reward: 2.1 DSV, halving every 216 blocks.
 */
void dsv_get_block_reward(dsv_u320_t *reward, int64_t height);

/**
 * Get current halving epoch.
 */
int64_t dsv_get_halving_epoch(int64_t height);

/**
 * Check if total supply is exceeded with this coinbase.
 */
bool dsv_check_supply_limit(const dsv_u320_t *coinbase_amount, int64_t height);

/* ==========================================================================
 * Difficulty / Target
 * ========================================================================== */

/**
 * Convert compact bits to 256-bit target.
 */
void dsv_bits_to_target(uint8_t target[32], uint32_t bits);

/**
 * Convert 256-bit target to compact bits.
 */
uint32_t dsv_target_to_bits(const uint8_t target[32]);

/**
 * Check if hash meets target.
 */
bool dsv_hash_meets_target(const dsv_hash256_t *hash, uint32_t bits);

/**
 * Calculate work from bits (for chainwork accumulation).
 */
void dsv_get_work_from_bits(dsv_chainwork_t *work, uint32_t bits);

/**
 * Add chainwork values.
 */
void dsv_chainwork_add(dsv_chainwork_t *result, 
                       const dsv_chainwork_t *a, 
                       const dsv_chainwork_t *b);

/**
 * Compare chainwork values.
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
int dsv_chainwork_cmp(const dsv_chainwork_t *a, const dsv_chainwork_t *b);

/**
 * Calculate new difficulty target for retarget.
 * Called every 2016 blocks.
 */
uint32_t dsv_calculate_next_bits(uint32_t prev_bits, 
                                  uint32_t first_block_time,
                                  uint32_t last_block_time);

/* ==========================================================================
 * Merkle Tree
 * ========================================================================== */

/**
 * Compute merkle root from transaction IDs.
 */
void dsv_compute_merkle_root(dsv_hash256_t *root, 
                              const dsv_hash256_t *txids, 
                              size_t tx_count);

/* ==========================================================================
 * Transaction Validation
 * ========================================================================== */

/**
 * Check transaction structure (not context-dependent).
 */
int dsv_tx_check_basic(const dsv_tx_t *tx);

/**
 * Verify transaction signatures.
 */
int dsv_tx_verify_signatures(const dsv_tx_t *tx);

/**
 * Check if transaction is coinbase.
 */
bool dsv_tx_is_coinbase(const dsv_tx_t *tx);

/* ==========================================================================
 * Block Validation
 * ========================================================================== */

/**
 * Check block header structure and PoW.
 */
int dsv_block_check_header(const dsv_block_header_t *header, uint32_t expected_bits);

/**
 * Check block structure (not context-dependent).
 */
int dsv_block_check_basic(const dsv_block_t *block);

/**
 * Validate coinbase transaction.
 */
int dsv_block_check_coinbase(const dsv_block_t *block, int64_t height,
                              const dsv_u320_t *fees);

/* ==========================================================================
 * Genesis Block
 * ========================================================================== */

/**
 * Get genesis block.
 */
dsv_block_t *dsv_get_genesis_block(void);

/**
 * Get genesis block hash.
 */
const dsv_hash256_t *dsv_get_genesis_hash(void);

/* ==========================================================================
 * Checkpoints
 * ========================================================================== */

typedef struct {
    int64_t height;
    dsv_hash256_t hash;
} dsv_checkpoint_t;

/**
 * Get checkpoint for height, or NULL if none.
 */
const dsv_checkpoint_t *dsv_get_checkpoint(int64_t height);

/**
 * Check if block matches checkpoint.
 */
bool dsv_verify_checkpoint(int64_t height, const dsv_hash256_t *hash);

#ifdef __cplusplus
}
#endif

#endif /* DSV_CONSENSUS_H */

