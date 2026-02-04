/**
 * DSV Memory Pool
 * 
 * Manages unconfirmed transactions waiting to be included in blocks.
 */

#ifndef DSV_MEMPOOL_H
#define DSV_MEMPOOL_H

#include "dsv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsv_mempool_s dsv_mempool_t;

/* ==========================================================================
 * Mempool Entry
 * ========================================================================== */

typedef struct {
    dsv_tx_t *tx;
    dsv_u320_t fee;
    uint64_t fee_per_byte;  /* For fee rate sorting */
    int64_t time_added;
    size_t tx_size;
} dsv_mempool_entry_t;

/* ==========================================================================
 * Mempool Operations
 * ========================================================================== */

/**
 * Create mempool.
 */
dsv_mempool_t *dsv_mempool_new(size_t max_size_mb);

/**
 * Destroy mempool.
 */
void dsv_mempool_free(dsv_mempool_t *mp);

/**
 * Add transaction to mempool.
 * Returns DSV_OK if accepted, error code otherwise.
 */
int dsv_mempool_add(dsv_mempool_t *mp, dsv_tx_t *tx, const dsv_u320_t *fee);

/**
 * Remove transaction from mempool.
 */
void dsv_mempool_remove(dsv_mempool_t *mp, const dsv_hash256_t *txid);

/**
 * Remove transactions included in a block.
 */
void dsv_mempool_remove_for_block(dsv_mempool_t *mp, const dsv_block_t *block);

/**
 * Re-add transactions after reorg.
 */
void dsv_mempool_reorg_add(dsv_mempool_t *mp, dsv_tx_t **txs, size_t count);

/**
 * Check if transaction is in mempool.
 */
bool dsv_mempool_contains(dsv_mempool_t *mp, const dsv_hash256_t *txid);

/**
 * Get transaction from mempool.
 */
dsv_tx_t *dsv_mempool_get(dsv_mempool_t *mp, const dsv_hash256_t *txid);

/**
 * Get mempool entry (with fee info).
 */
dsv_mempool_entry_t *dsv_mempool_get_entry(dsv_mempool_t *mp, 
                                            const dsv_hash256_t *txid);

/**
 * Get transactions for block template (sorted by fee rate).
 */
dsv_tx_t **dsv_mempool_get_block_template(dsv_mempool_t *mp,
                                           size_t max_size,
                                           dsv_u320_t *total_fees,
                                           size_t *count);

/**
 * Get number of transactions in mempool.
 */
size_t dsv_mempool_size(dsv_mempool_t *mp);

/**
 * Get total memory usage.
 */
size_t dsv_mempool_memory_usage(dsv_mempool_t *mp);

/**
 * Clear all transactions.
 */
void dsv_mempool_clear(dsv_mempool_t *mp);

/**
 * Check if UTXO is spent by a mempool transaction.
 */
bool dsv_mempool_is_spent(dsv_mempool_t *mp,
                          const dsv_hash256_t *txid,
                          uint32_t vout);

/**
 * Free mempool entry.
 */
void dsv_mempool_entry_free(dsv_mempool_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* DSV_MEMPOOL_H */

