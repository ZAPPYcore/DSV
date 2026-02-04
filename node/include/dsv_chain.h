/**
 * DSV Chain State Manager
 * 
 * Manages the blockchain state including:
 * - Block validation and connection
 * - Chain reorganization
 * - UTXO set management
 */

#ifndef DSV_CHAIN_H
#define DSV_CHAIN_H

#include "dsv_types.h"
#include "dsv_storage.h"
#include "dsv_mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsv_chain_s dsv_chain_t;

/* ==========================================================================
 * Chain State Events (callbacks)
 * ========================================================================== */

typedef void (*dsv_block_connected_cb)(const dsv_block_t *block, 
                                        int64_t height, void *ctx);
typedef void (*dsv_block_disconnected_cb)(const dsv_block_t *block,
                                           int64_t height, void *ctx);
typedef void (*dsv_chain_tip_cb)(const dsv_hash256_t *hash,
                                  int64_t height, void *ctx);

/* ==========================================================================
 * Chain Initialization
 * ========================================================================== */

/**
 * Create chain state manager.
 */
dsv_chain_t *dsv_chain_new(const char *data_dir);

/**
 * Destroy chain state manager.
 */
void dsv_chain_free(dsv_chain_t *chain);

/**
 * Set mempool reference.
 */
void dsv_chain_set_mempool(dsv_chain_t *chain, dsv_mempool_t *mempool);

/**
 * Set callbacks.
 */
void dsv_chain_set_callbacks(dsv_chain_t *chain,
                              dsv_block_connected_cb on_connect,
                              dsv_block_disconnected_cb on_disconnect,
                              dsv_chain_tip_cb on_tip,
                              void *ctx);

/* ==========================================================================
 * Chain State Queries
 * ========================================================================== */

/**
 * Get current best block hash.
 */
int dsv_chain_get_best_hash(dsv_chain_t *chain, dsv_hash256_t *hash);

/**
 * Get current best block height.
 */
int64_t dsv_chain_get_height(dsv_chain_t *chain);

/**
 * Get current chainwork.
 */
int dsv_chain_get_chainwork(dsv_chain_t *chain, dsv_chainwork_t *work);

/**
 * Get block index by hash.
 */
dsv_block_index_t *dsv_chain_get_block_index(dsv_chain_t *chain,
                                              const dsv_hash256_t *hash);

/**
 * Get block index by height.
 */
dsv_block_index_t *dsv_chain_get_block_at_height(dsv_chain_t *chain,
                                                  int64_t height);

/**
 * Get block by hash.
 */
dsv_block_t *dsv_chain_get_block(dsv_chain_t *chain,
                                  const dsv_hash256_t *hash);

/**
 * Check if block is on main chain.
 */
bool dsv_chain_is_main_chain(dsv_chain_t *chain, const dsv_hash256_t *hash);

/**
 * Get current difficulty bits.
 */
uint32_t dsv_chain_get_current_bits(dsv_chain_t *chain);

/* ==========================================================================
 * Block Processing
 * ========================================================================== */

/**
 * Accept block - validate and potentially add to chain.
 * Returns DSV_OK if block was accepted (may not be on main chain).
 */
int dsv_chain_accept_block(dsv_chain_t *chain, dsv_block_t *block);

/**
 * Process new block header.
 */
int dsv_chain_process_header(dsv_chain_t *chain, 
                              const dsv_block_header_t *header);

/**
 * Validate block (full validation with UTXO checks).
 */
int dsv_chain_validate_block(dsv_chain_t *chain, 
                              const dsv_block_t *block,
                              int64_t height);

/* ==========================================================================
 * UTXO Access
 * ========================================================================== */

/**
 * Get UTXO from chain state.
 */
dsv_utxo_t *dsv_chain_get_utxo(dsv_chain_t *chain,
                                const dsv_hash256_t *txid,
                                uint32_t vout);

/**
 * Get all UTXOs for an address.
 */
dsv_utxo_t **dsv_chain_get_address_utxos(dsv_chain_t *chain,
                                          const dsv_address_t *addr,
                                          size_t *count);

/**
 * Get address balance.
 */
int dsv_chain_get_balance(dsv_chain_t *chain,
                           const dsv_address_t *addr,
                           dsv_u320_t *balance);

/* ==========================================================================
 * Transaction Validation
 * ========================================================================== */

/**
 * Validate transaction against current chain state.
 */
int dsv_chain_validate_tx(dsv_chain_t *chain, const dsv_tx_t *tx,
                           dsv_u320_t *fee);

/**
 * Check if transaction inputs are available.
 */
bool dsv_chain_are_inputs_available(dsv_chain_t *chain, const dsv_tx_t *tx);

/* ==========================================================================
 * Mining Support
 * ========================================================================== */

/**
 * Create block template for mining.
 */
dsv_block_t *dsv_chain_create_block_template(dsv_chain_t *chain,
                                              const dsv_address_t *coinbase_addr);

/**
 * Submit mined block.
 */
int dsv_chain_submit_block(dsv_chain_t *chain, dsv_block_t *block);

#ifdef __cplusplus
}
#endif

#endif /* DSV_CHAIN_H */

