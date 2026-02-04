/**
 * DSV Storage Layer
 * 
 * Design decision: Using LevelDB over RocksDB
 * - Simpler API and smaller footprint
 * - Well-tested in production (Bitcoin Core used LevelDB for years)
 * - Sufficient for our UTXO workload
 * - Easier to compile and deploy
 */

#ifndef DSV_STORAGE_H
#define DSV_STORAGE_H

#include "dsv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Storage Handle
 * ========================================================================== */

typedef struct dsv_storage_s dsv_storage_t;

/* ==========================================================================
 * Database Initialization
 * ========================================================================== */

/**
 * Open storage at given path.
 */
dsv_storage_t *dsv_storage_open(const char *path);

/**
 * Close storage.
 */
void dsv_storage_close(dsv_storage_t *storage);

/* ==========================================================================
 * Block Index Database
 * ========================================================================== */

/**
 * Store block index entry.
 */
int dsv_storage_put_block_index(dsv_storage_t *storage, 
                                 const dsv_block_index_t *index);

/**
 * Get block index by hash.
 */
dsv_block_index_t *dsv_storage_get_block_index(dsv_storage_t *storage,
                                                const dsv_hash256_t *hash);

/**
 * Get block index by height (on main chain).
 */
dsv_block_index_t *dsv_storage_get_block_at_height(dsv_storage_t *storage,
                                                    int64_t height);

/**
 * Store best chain tip hash.
 */
int dsv_storage_put_best_block(dsv_storage_t *storage,
                                const dsv_hash256_t *hash);

/**
 * Get best chain tip hash.
 */
int dsv_storage_get_best_block(dsv_storage_t *storage, dsv_hash256_t *hash);

/**
 * Free block index.
 */
void dsv_block_index_free(dsv_block_index_t *index);

/* ==========================================================================
 * UTXO Database
 * ========================================================================== */

/**
 * Store UTXO.
 */
int dsv_storage_put_utxo(dsv_storage_t *storage, const dsv_utxo_t *utxo);

/**
 * Get UTXO by outpoint.
 */
dsv_utxo_t *dsv_storage_get_utxo(dsv_storage_t *storage,
                                  const dsv_hash256_t *txid,
                                  uint32_t vout);

/**
 * Delete UTXO (when spent).
 */
int dsv_storage_delete_utxo(dsv_storage_t *storage,
                             const dsv_hash256_t *txid,
                             uint32_t vout);

/**
 * Get all UTXOs for an address.
 */
dsv_utxo_t **dsv_storage_get_utxos_for_address(dsv_storage_t *storage,
                                                const dsv_address_t *addr,
                                                size_t *count);

/**
 * Free UTXO.
 */
void dsv_utxo_free(dsv_utxo_t *utxo);

/**
 * Free UTXO array.
 */
void dsv_utxo_array_free(dsv_utxo_t **utxos, size_t count);

/* ==========================================================================
 * Block Files
 * ========================================================================== */

/**
 * Block file manager.
 */
typedef struct dsv_blockfile_s dsv_blockfile_t;

/**
 * Open block file manager.
 */
dsv_blockfile_t *dsv_blockfile_open(const char *dir);

/**
 * Close block file manager.
 */
void dsv_blockfile_close(dsv_blockfile_t *bf);

/**
 * Write block to file, returns file_no and file_offset.
 */
int dsv_blockfile_write_block(dsv_blockfile_t *bf,
                               const dsv_block_t *block,
                               uint64_t *file_no,
                               uint64_t *file_offset);

/**
 * Read block from file.
 */
dsv_block_t *dsv_blockfile_read_block(dsv_blockfile_t *bf,
                                       uint64_t file_no,
                                       uint64_t file_offset);

/* ==========================================================================
 * Undo Data (for reorgs)
 * ========================================================================== */

typedef struct {
    dsv_hash256_t block_hash;
    size_t spent_count;
    dsv_utxo_t *spent_utxos;  /* UTXOs that were spent in this block */
} dsv_undo_data_t;

/**
 * Store undo data for block.
 */
int dsv_storage_put_undo(dsv_storage_t *storage, const dsv_undo_data_t *undo);

/**
 * Get undo data for block.
 */
dsv_undo_data_t *dsv_storage_get_undo(dsv_storage_t *storage,
                                       const dsv_hash256_t *block_hash);

/**
 * Delete undo data.
 */
int dsv_storage_delete_undo(dsv_storage_t *storage,
                             const dsv_hash256_t *block_hash);

/**
 * Free undo data.
 */
void dsv_undo_data_free(dsv_undo_data_t *undo);

/* ==========================================================================
 * Batch Operations
 * ========================================================================== */

typedef struct dsv_write_batch_s dsv_write_batch_t;

/**
 * Create write batch.
 */
dsv_write_batch_t *dsv_write_batch_new(void);

/**
 * Add UTXO to batch.
 */
int dsv_write_batch_put_utxo(dsv_write_batch_t *batch, const dsv_utxo_t *utxo);

/**
 * Delete UTXO in batch.
 */
int dsv_write_batch_delete_utxo(dsv_write_batch_t *batch,
                                 const dsv_hash256_t *txid,
                                 uint32_t vout);

/**
 * Execute batch.
 */
int dsv_write_batch_execute(dsv_storage_t *storage, dsv_write_batch_t *batch);

/**
 * Free batch.
 */
void dsv_write_batch_free(dsv_write_batch_t *batch);

/* ==========================================================================
 * Pruning
 * ========================================================================== */

/**
 * Enable pruning mode.
 */
void dsv_storage_set_prune_mode(dsv_storage_t *storage, bool enabled,
                                 uint64_t target_size_mb);

/**
 * Check if block data can be pruned.
 */
bool dsv_storage_can_prune_block(dsv_storage_t *storage, int64_t height);

/**
 * Prune old block files.
 */
int dsv_storage_prune_blocks(dsv_storage_t *storage, int64_t height);

#ifdef __cplusplus
}
#endif

#endif /* DSV_STORAGE_H */

