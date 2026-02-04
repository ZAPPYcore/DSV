/**
 * DSV Chain State Manager Implementation
 */

#include <stdio.h>
#include "dsv_chain.h"
#include "dsv_consensus.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"
#include "dsv_u320.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

struct dsv_chain_s {
    dsv_storage_t *storage;
    dsv_blockfile_t *blockfiles;
    dsv_mempool_t *mempool;
    
    /* Current chain tip */
    dsv_hash256_t best_hash;
    int64_t best_height;
    dsv_chainwork_t best_chainwork;
    uint32_t current_bits;
    
    /* Callbacks */
    dsv_block_connected_cb on_connect;
    dsv_block_disconnected_cb on_disconnect;
    dsv_chain_tip_cb on_tip;
    void *callback_ctx;
    
    /* Thread safety */
    pthread_rwlock_t lock;
    
    char *data_dir;
};

/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

static void update_best_chain(dsv_chain_t *chain, const dsv_block_index_t *idx) {
    chain->best_hash = idx->hash;
    chain->best_height = idx->height;
    memcpy(&chain->best_chainwork, &idx->chainwork, sizeof(dsv_chainwork_t));
    chain->current_bits = idx->bits;
    
    dsv_storage_put_best_block(chain->storage, &idx->hash);
    
    if (chain->on_tip) {
        chain->on_tip(&idx->hash, idx->height, chain->callback_ctx);
    }
}

static int connect_block(dsv_chain_t *chain, dsv_block_t *block,
                         dsv_block_index_t *idx) {
    int64_t height = idx->height;
    
    /* Create undo data for reorg support */
    dsv_undo_data_t undo;
    undo.block_hash = idx->hash;
    undo.spent_count = 0;
    
    /* Count total inputs to preallocate */
    size_t total_inputs = 0;
    for (uint32_t i = 0; i < block->tx_count; i++) {
        if (!dsv_tx_is_coinbase(block->txs[i])) {
            total_inputs += block->txs[i]->input_count;
        }
    }
    
    if (total_inputs > 0) {
        undo.spent_utxos = calloc(total_inputs, sizeof(dsv_utxo_t));
        if (!undo.spent_utxos) return DSV_ERR_NOMEM;
    } else {
        undo.spent_utxos = NULL;
    }
    
    /* Process transactions */
    dsv_write_batch_t *batch = dsv_write_batch_new();
    if (!batch) {
        free(undo.spent_utxos);
        return DSV_ERR_NOMEM;
    }
    
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_tx_t *tx = block->txs[i];
        dsv_hash256_t txid;
        dsv_tx_compute_txid(&txid, tx);
        
        /* Spend inputs (except for coinbase) */
        if (!dsv_tx_is_coinbase(tx)) {
            for (uint32_t j = 0; j < tx->input_count; j++) {
                dsv_utxo_t *utxo = dsv_storage_get_utxo(chain->storage,
                    &tx->inputs[j].prev_txid, tx->inputs[j].prev_vout);
                
                if (utxo) {
                    /* Save for undo */
                    memcpy(&undo.spent_utxos[undo.spent_count++], utxo, sizeof(dsv_utxo_t));
                    
                    /* Remove from UTXO set */
                    dsv_write_batch_delete_utxo(batch,
                        &tx->inputs[j].prev_txid, tx->inputs[j].prev_vout);
                    
                    dsv_utxo_free(utxo);
                }
            }
        }
        
        /* Create new UTXOs */
        for (uint32_t j = 0; j < tx->output_count; j++) {
            dsv_utxo_t new_utxo;
            new_utxo.txid = txid;
            new_utxo.vout = j;
            dsv_u320_copy(&new_utxo.amount, &tx->outputs[j].amount);
            new_utxo.address = tx->outputs[j].address;
            new_utxo.height = height;
            new_utxo.is_coinbase = dsv_tx_is_coinbase(tx);
            
            dsv_write_batch_put_utxo(batch, &new_utxo);
        }
    }
    
    /* Execute batch write */
    int err = dsv_write_batch_execute(chain->storage, batch);
    dsv_write_batch_free(batch);
    
    if (err != DSV_OK) {
        free(undo.spent_utxos);
        return err;
    }
    
    /* Store undo data */
    dsv_storage_put_undo(chain->storage, &undo);
    free(undo.spent_utxos);
    
    /* Update block index */
    idx->on_main_chain = true;
    dsv_storage_put_block_index(chain->storage, idx);
    
    /* Remove transactions from mempool */
    if (chain->mempool) {
        dsv_mempool_remove_for_block(chain->mempool, block);
    }
    
    /* Callback */
    if (chain->on_connect) {
        chain->on_connect(block, height, chain->callback_ctx);
    }
    
    return DSV_OK;
}

static int disconnect_block(dsv_chain_t *chain, const dsv_hash256_t *hash) {
    dsv_block_index_t *idx = dsv_storage_get_block_index(chain->storage, hash);
    if (!idx) return DSV_ERR_NOT_FOUND;
    
    dsv_block_t *block = dsv_blockfile_read_block(chain->blockfiles,
                                                   idx->file_no, idx->file_offset);
    if (!block) {
        dsv_block_index_free(idx);
        return DSV_ERR_NOT_FOUND;
    }
    
    /* Get undo data */
    dsv_undo_data_t *undo = dsv_storage_get_undo(chain->storage, hash);
    if (!undo) {
        dsv_block_free(block);
        dsv_block_index_free(idx);
        return DSV_ERR_NOT_FOUND;
    }
    
    dsv_write_batch_t *batch = dsv_write_batch_new();
    if (!batch) {
        dsv_undo_data_free(undo);
        dsv_block_free(block);
        dsv_block_index_free(idx);
        return DSV_ERR_NOMEM;
    }
    
    /* Remove outputs created by this block */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_hash256_t txid;
        dsv_tx_compute_txid(&txid, block->txs[i]);
        
        for (uint32_t j = 0; j < block->txs[i]->output_count; j++) {
            dsv_write_batch_delete_utxo(batch, &txid, j);
        }
    }
    
    /* Restore spent UTXOs */
    for (size_t i = 0; i < undo->spent_count; i++) {
        dsv_write_batch_put_utxo(batch, &undo->spent_utxos[i]);
    }
    
    int err = dsv_write_batch_execute(chain->storage, batch);
    dsv_write_batch_free(batch);
    
    if (err != DSV_OK) {
        dsv_undo_data_free(undo);
        dsv_block_free(block);
        dsv_block_index_free(idx);
        return err;
    }
    
    /* Update block index */
    idx->on_main_chain = false;
    dsv_storage_put_block_index(chain->storage, idx);
    
    /* Delete undo data */
    dsv_storage_delete_undo(chain->storage, hash);
    
    /* Re-add transactions to mempool */
    if (chain->mempool) {
        dsv_mempool_reorg_add(chain->mempool, block->txs, block->tx_count);
    }
    
    /* Callback */
    if (chain->on_disconnect) {
        chain->on_disconnect(block, idx->height, chain->callback_ctx);
    }
    
    dsv_undo_data_free(undo);
    dsv_block_free(block);
    dsv_block_index_free(idx);
    
    return DSV_OK;
}

static int reorganize(dsv_chain_t *chain, dsv_block_index_t *new_tip) {
    /* Find fork point */
    dsv_block_index_t *old_tip = dsv_storage_get_block_index(chain->storage,
                                                              &chain->best_hash);
    if (!old_tip) return DSV_ERR_NOT_FOUND;
    
    /* Build list of blocks to disconnect and connect */
    dsv_hash256_t *to_disconnect = NULL;
    size_t disconnect_count = 0;
    dsv_hash256_t *to_connect = NULL;
    size_t connect_count = 0;
    
    dsv_block_index_t *walk_old = old_tip;
    dsv_block_index_t *walk_new = new_tip;
    
    /* Walk back to common ancestor */
    while (walk_old->height > walk_new->height) {
        to_disconnect = realloc(to_disconnect, 
                                (disconnect_count + 1) * sizeof(dsv_hash256_t));
        to_disconnect[disconnect_count++] = walk_old->hash;
        
        dsv_block_index_t *prev = dsv_storage_get_block_index(chain->storage,
                                                               &walk_old->prev_hash);
        dsv_block_index_free(walk_old);
        walk_old = prev;
    }
    
    while (walk_new->height > walk_old->height) {
        to_connect = realloc(to_connect,
                             (connect_count + 1) * sizeof(dsv_hash256_t));
        to_connect[connect_count++] = walk_new->hash;
        
        dsv_block_index_t *prev = dsv_storage_get_block_index(chain->storage,
                                                               &walk_new->prev_hash);
        dsv_block_index_free(walk_new);
        walk_new = prev;
    }
    
    while (!dsv_hash_eq(&walk_old->hash, &walk_new->hash)) {
        to_disconnect = realloc(to_disconnect,
                                (disconnect_count + 1) * sizeof(dsv_hash256_t));
        to_disconnect[disconnect_count++] = walk_old->hash;
        
        to_connect = realloc(to_connect,
                             (connect_count + 1) * sizeof(dsv_hash256_t));
        to_connect[connect_count++] = walk_new->hash;
        
        dsv_block_index_t *prev_old = dsv_storage_get_block_index(chain->storage,
                                                                   &walk_old->prev_hash);
        dsv_block_index_t *prev_new = dsv_storage_get_block_index(chain->storage,
                                                                   &walk_new->prev_hash);
        dsv_block_index_free(walk_old);
        dsv_block_index_free(walk_new);
        walk_old = prev_old;
        walk_new = prev_new;
    }
    
    dsv_block_index_free(walk_old);
    dsv_block_index_free(walk_new);
    
    /* Disconnect blocks */
    for (size_t i = 0; i < disconnect_count; i++) {
        int err = disconnect_block(chain, &to_disconnect[i]);
        if (err != DSV_OK) {
            free(to_disconnect);
            free(to_connect);
            return err;
        }
    }
    
    /* Connect blocks (in reverse order) */
    for (size_t i = connect_count; i > 0; i--) {
        dsv_block_index_t *idx = dsv_storage_get_block_index(chain->storage,
                                                              &to_connect[i - 1]);
        dsv_block_t *block = dsv_blockfile_read_block(chain->blockfiles,
                                                       idx->file_no, idx->file_offset);
        
        int err = connect_block(chain, block, idx);
        dsv_block_free(block);
        
        if (err != DSV_OK) {
            dsv_block_index_free(idx);
            free(to_disconnect);
            free(to_connect);
            return err;
        }
        
        dsv_block_index_free(idx);
    }
    
    free(to_disconnect);
    free(to_connect);
    
    return DSV_OK;
}

/* ==========================================================================
 * Chain Initialization
 * ========================================================================== */

dsv_chain_t *dsv_chain_new(const char *data_dir) {
    dsv_chain_t *chain = calloc(1, sizeof(dsv_chain_t));
    if (!chain) return NULL;
    
    chain->data_dir = strdup(data_dir);
    if (!chain->data_dir) {
        free(chain);
        return NULL;
    }
    
    /* Open storage */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/chainstate", data_dir);
    chain->storage = dsv_storage_open(db_path);
    if (!chain->storage) {
        free(chain->data_dir);
        free(chain);
        return NULL;
    }
    
    /* Open block files */
    char blocks_path[512];
    snprintf(blocks_path, sizeof(blocks_path), "%s/blocks", data_dir);
    chain->blockfiles = dsv_blockfile_open(blocks_path);
    if (!chain->blockfiles) {
        dsv_storage_close(chain->storage);
        free(chain->data_dir);
        free(chain);
        return NULL;
    }
    
    pthread_rwlock_init(&chain->lock, NULL);
    
    /* Load best block or initialize with genesis */
    if (dsv_storage_get_best_block(chain->storage, &chain->best_hash) != DSV_OK) {
        /* Initialize with genesis */
        dsv_block_t *genesis = dsv_get_genesis_block();
        if (genesis) {
            dsv_block_compute_hash(&chain->best_hash, &genesis->header);
            
            /* Store genesis block */
            uint64_t file_no, file_offset;
            dsv_blockfile_write_block(chain->blockfiles, genesis, 
                                      &file_no, &file_offset);
            
            /* Create index entry */
            dsv_block_index_t idx;
            memset(&idx, 0, sizeof(idx));
            idx.hash = chain->best_hash;
            idx.prev_hash = DSV_HASH_ZERO;
            idx.height = 0;
            idx.timestamp = genesis->header.timestamp;
            idx.bits = genesis->header.bits;
            idx.nonce = genesis->header.nonce;
            idx.file_no = file_no;
            idx.file_offset = file_offset;
            idx.tx_count = genesis->tx_count;
            idx.on_main_chain = true;
            
            dsv_get_work_from_bits(&idx.chainwork, idx.bits);
            
            dsv_storage_put_block_index(chain->storage, &idx);
            dsv_storage_put_best_block(chain->storage, &chain->best_hash);
            
            /* Add genesis coinbase UTXO */
            if (genesis->tx_count > 0 && genesis->txs[0]->output_count > 0) {
                dsv_utxo_t utxo;
                dsv_tx_compute_txid(&utxo.txid, genesis->txs[0]);
                utxo.vout = 0;
                dsv_u320_copy(&utxo.amount, &genesis->txs[0]->outputs[0].amount);
                utxo.address = genesis->txs[0]->outputs[0].address;
                utxo.height = 0;
                utxo.is_coinbase = true;
                dsv_storage_put_utxo(chain->storage, &utxo);
            }
            
            chain->best_height = 0;
            memcpy(&chain->best_chainwork, &idx.chainwork, sizeof(dsv_chainwork_t));
            chain->current_bits = genesis->header.bits;
        }
    } else {
        /* Load existing chain state */
        dsv_block_index_t *best = dsv_storage_get_block_index(chain->storage,
                                                               &chain->best_hash);
        if (best) {
            chain->best_height = best->height;
            memcpy(&chain->best_chainwork, &best->chainwork, sizeof(dsv_chainwork_t));
            chain->current_bits = best->bits;
            dsv_block_index_free(best);
        }
    }
    
    return chain;
}

void dsv_chain_free(dsv_chain_t *chain) {
    if (!chain) return;
    
    pthread_rwlock_destroy(&chain->lock);
    
    if (chain->blockfiles) dsv_blockfile_close(chain->blockfiles);
    if (chain->storage) dsv_storage_close(chain->storage);
    free(chain->data_dir);
    free(chain);
}

void dsv_chain_set_mempool(dsv_chain_t *chain, dsv_mempool_t *mempool) {
    chain->mempool = mempool;
}

void dsv_chain_set_callbacks(dsv_chain_t *chain,
                              dsv_block_connected_cb on_connect,
                              dsv_block_disconnected_cb on_disconnect,
                              dsv_chain_tip_cb on_tip,
                              void *ctx) {
    chain->on_connect = on_connect;
    chain->on_disconnect = on_disconnect;
    chain->on_tip = on_tip;
    chain->callback_ctx = ctx;
}

/* ==========================================================================
 * Chain State Queries
 * ========================================================================== */

int dsv_chain_get_best_hash(dsv_chain_t *chain, dsv_hash256_t *hash) {
    pthread_rwlock_rdlock(&chain->lock);
    *hash = chain->best_hash;
    pthread_rwlock_unlock(&chain->lock);
    return DSV_OK;
}

int64_t dsv_chain_get_height(dsv_chain_t *chain) {
    pthread_rwlock_rdlock(&chain->lock);
    int64_t height = chain->best_height;
    pthread_rwlock_unlock(&chain->lock);
    return height;
}

int dsv_chain_get_chainwork(dsv_chain_t *chain, dsv_chainwork_t *work) {
    pthread_rwlock_rdlock(&chain->lock);
    memcpy(work, &chain->best_chainwork, sizeof(dsv_chainwork_t));
    pthread_rwlock_unlock(&chain->lock);
    return DSV_OK;
}

dsv_block_index_t *dsv_chain_get_block_index(dsv_chain_t *chain,
                                              const dsv_hash256_t *hash) {
    pthread_rwlock_rdlock(&chain->lock);
    dsv_block_index_t *idx = dsv_storage_get_block_index(chain->storage, hash);
    pthread_rwlock_unlock(&chain->lock);
    return idx;
}

dsv_block_index_t *dsv_chain_get_block_at_height(dsv_chain_t *chain,
                                                  int64_t height) {
    pthread_rwlock_rdlock(&chain->lock);
    dsv_block_index_t *idx = dsv_storage_get_block_at_height(chain->storage, height);
    pthread_rwlock_unlock(&chain->lock);
    return idx;
}

dsv_block_t *dsv_chain_get_block(dsv_chain_t *chain, const dsv_hash256_t *hash) {
    pthread_rwlock_rdlock(&chain->lock);
    dsv_block_index_t *idx = dsv_storage_get_block_index(chain->storage, hash);
    if (!idx) {
        pthread_rwlock_unlock(&chain->lock);
        return NULL;
    }
    
    dsv_block_t *block = dsv_blockfile_read_block(chain->blockfiles,
                                                   idx->file_no, idx->file_offset);
    dsv_block_index_free(idx);
    pthread_rwlock_unlock(&chain->lock);
    return block;
}

bool dsv_chain_is_main_chain(dsv_chain_t *chain, const dsv_hash256_t *hash) {
    dsv_block_index_t *idx = dsv_chain_get_block_index(chain, hash);
    if (!idx) return false;
    bool on_main = idx->on_main_chain;
    dsv_block_index_free(idx);
    return on_main;
}

uint32_t dsv_chain_get_current_bits(dsv_chain_t *chain) {
    pthread_rwlock_rdlock(&chain->lock);
    
    int64_t height = chain->best_height + 1;
    uint32_t bits = chain->current_bits;
    
    /* Check if retarget is needed */
    if (height % DSV_RETARGET_INTERVAL == 0 && height > 0) {
        /* Get first and last block of the interval */
        dsv_block_index_t *first = dsv_storage_get_block_at_height(
            chain->storage, height - DSV_RETARGET_INTERVAL);
        dsv_block_index_t *last = dsv_storage_get_block_at_height(
            chain->storage, height - 1);
        
        if (first && last) {
            bits = dsv_calculate_next_bits(last->bits, 
                                            first->timestamp, last->timestamp);
        }
        
        if (first) dsv_block_index_free(first);
        if (last) dsv_block_index_free(last);
    }
    
    pthread_rwlock_unlock(&chain->lock);
    return bits;
}

/* ==========================================================================
 * Block Processing
 * ========================================================================== */

int dsv_chain_accept_block(dsv_chain_t *chain, dsv_block_t *block) {
    pthread_rwlock_wrlock(&chain->lock);
    
    /* Compute block hash */
    dsv_hash256_t hash;
    dsv_block_compute_hash(&hash, &block->header);
    
    /* Check if already have this block */
    dsv_block_index_t *existing = dsv_storage_get_block_index(chain->storage, &hash);
    if (existing) {
        dsv_block_index_free(existing);
        pthread_rwlock_unlock(&chain->lock);
        return DSV_ERR_DUPLICATE;
    }
    
    /* Get parent block */
    dsv_block_index_t *parent = dsv_storage_get_block_index(chain->storage,
                                                             &block->header.prev_hash);
    if (!parent && !dsv_hash_is_zero(&block->header.prev_hash)) {
        pthread_rwlock_unlock(&chain->lock);
        return DSV_ERR_NOT_FOUND;  /* Missing parent - orphan block */
    }
    
    int64_t height = parent ? parent->height + 1 : 0;
    
    /* Validate block header */
    uint32_t expected_bits = chain->current_bits;
    if (height % DSV_RETARGET_INTERVAL == 0 && height > 0) {
        dsv_block_index_t *first = dsv_storage_get_block_at_height(
            chain->storage, height - DSV_RETARGET_INTERVAL);
        if (first && parent) {
            expected_bits = dsv_calculate_next_bits(parent->bits,
                                                     first->timestamp, parent->timestamp);
            dsv_block_index_free(first);
        }
    }
    
    int err = dsv_block_check_header(&block->header, expected_bits);
    if (err != DSV_OK) {
        if (parent) dsv_block_index_free(parent);
        pthread_rwlock_unlock(&chain->lock);
        return err;
    }
    
    /* Check basic block structure */
    err = dsv_block_check_basic(block);
    if (err != DSV_OK) {
        if (parent) dsv_block_index_free(parent);
        pthread_rwlock_unlock(&chain->lock);
        return err;
    }
    
    /* Check checkpoint */
    if (!dsv_verify_checkpoint(height, &hash)) {
        if (parent) dsv_block_index_free(parent);
        pthread_rwlock_unlock(&chain->lock);
        return DSV_ERR_CONSENSUS;
    }
    
    /* Write block to disk */
    uint64_t file_no, file_offset;
    err = dsv_blockfile_write_block(chain->blockfiles, block, &file_no, &file_offset);
    if (err != DSV_OK) {
        if (parent) dsv_block_index_free(parent);
        pthread_rwlock_unlock(&chain->lock);
        return err;
    }
    
    /* Create block index */
    dsv_block_index_t idx;
    memset(&idx, 0, sizeof(idx));
    idx.hash = hash;
    idx.prev_hash = block->header.prev_hash;
    idx.height = height;
    idx.timestamp = block->header.timestamp;
    idx.bits = block->header.bits;
    idx.nonce = block->header.nonce;
    idx.file_no = file_no;
    idx.file_offset = file_offset;
    idx.tx_count = block->tx_count;
    idx.on_main_chain = false;
    
    /* Calculate chainwork */
    dsv_chainwork_t block_work;
    dsv_get_work_from_bits(&block_work, idx.bits);
    if (parent) {
        dsv_chainwork_add(&idx.chainwork, &parent->chainwork, &block_work);
    } else {
        memcpy(&idx.chainwork, &block_work, sizeof(dsv_chainwork_t));
    }
    
    dsv_storage_put_block_index(chain->storage, &idx);
    
    /* Check if this becomes new best chain */
    if (dsv_chainwork_cmp(&idx.chainwork, &chain->best_chainwork) > 0) {
        /* New best chain */
        if (parent && dsv_hash_eq(&block->header.prev_hash, &chain->best_hash)) {
            /* Extends current best - simple connect */
            err = dsv_chain_validate_block(chain, block, height);
            if (err != DSV_OK) {
                if (parent) dsv_block_index_free(parent);
                pthread_rwlock_unlock(&chain->lock);
                return err;
            }
            
            err = connect_block(chain, block, &idx);
            if (err == DSV_OK) {
                update_best_chain(chain, &idx);
            }
        } else {
            /* Requires reorganization */
            dsv_block_index_t *new_idx = dsv_storage_get_block_index(chain->storage, &hash);
            if (new_idx) {
                err = reorganize(chain, new_idx);
                if (err == DSV_OK) {
                    update_best_chain(chain, new_idx);
                }
                dsv_block_index_free(new_idx);
            }
        }
    }
    
    if (parent) dsv_block_index_free(parent);
    pthread_rwlock_unlock(&chain->lock);
    
    return DSV_OK;
}

int dsv_chain_process_header(dsv_chain_t *chain,
                              const dsv_block_header_t *header) {
    dsv_hash256_t hash;
    dsv_block_compute_hash(&hash, header);
    
    pthread_rwlock_rdlock(&chain->lock);
    dsv_block_index_t *existing = dsv_storage_get_block_index(chain->storage, &hash);
    pthread_rwlock_unlock(&chain->lock);
    
    if (existing) {
        dsv_block_index_free(existing);
        return DSV_OK;  /* Already have it */
    }
    
    /* Would need full block to process */
    return DSV_ERR_NOT_FOUND;
}

int dsv_chain_validate_block(dsv_chain_t *chain,
                              const dsv_block_t *block,
                              int64_t height) {
    dsv_u320_t total_fees = DSV_U320_ZERO;
    
    /* Validate each transaction */
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_tx_t *tx = block->txs[i];
        
        if (i == 0) {
            /* Coinbase validation is separate */
            continue;
        }
        
        /* Verify signatures */
        int err = dsv_tx_verify_signatures(tx);
        if (err != DSV_OK) return err;
        
        /* Check inputs exist and compute fee */
        dsv_u320_t input_sum = DSV_U320_ZERO;
        dsv_u320_t output_sum = DSV_U320_ZERO;
        
        for (uint32_t j = 0; j < tx->input_count; j++) {
            dsv_utxo_t *utxo = dsv_storage_get_utxo(chain->storage,
                &tx->inputs[j].prev_txid, tx->inputs[j].prev_vout);
            
            if (!utxo) {
                /* Check if created in this block */
                bool found_in_block = false;
                for (uint32_t k = 0; k < i; k++) {
                    dsv_hash256_t prev_txid;
                    dsv_tx_compute_txid(&prev_txid, block->txs[k]);
                    if (dsv_hash_eq(&prev_txid, &tx->inputs[j].prev_txid) &&
                        tx->inputs[j].prev_vout < block->txs[k]->output_count) {
                        dsv_u320_add(&input_sum, &input_sum,
                                     &block->txs[k]->outputs[tx->inputs[j].prev_vout].amount);
                        found_in_block = true;
                        break;
                    }
                }
                if (!found_in_block) return DSV_ERR_NOT_FOUND;
                continue;
            }
            
            /* Check coinbase maturity */
            if (utxo->is_coinbase && height - utxo->height < DSV_COINBASE_MATURITY) {
                dsv_utxo_free(utxo);
                return DSV_ERR_CONSENSUS;
            }
            
            /* Verify pubkey matches address */
            dsv_address_t derived_addr;
            dsv_address_from_pubkey(&derived_addr, &tx->inputs[j].pubkey,
                                    utxo->address.version);
            if (!dsv_address_eq(&derived_addr, &utxo->address)) {
                dsv_utxo_free(utxo);
                return DSV_ERR_VERIFY;
            }
            
            dsv_u320_add(&input_sum, &input_sum, &utxo->amount);
            dsv_utxo_free(utxo);
        }
        
        for (uint32_t j = 0; j < tx->output_count; j++) {
            dsv_u320_add(&output_sum, &output_sum, &tx->outputs[j].amount);
        }
        
        /* inputs must >= outputs */
        if (dsv_u320_cmp(&input_sum, &output_sum) < 0) {
            return DSV_ERR_CONSENSUS;
        }
        
        /* Add fee */
        dsv_u320_t fee;
        dsv_u320_sub(&fee, &input_sum, &output_sum);
        dsv_u320_add(&total_fees, &total_fees, &fee);
    }
    
    /* Validate coinbase */
    return dsv_block_check_coinbase(block, height, &total_fees);
}

/* ==========================================================================
 * UTXO Access
 * ========================================================================== */

dsv_utxo_t *dsv_chain_get_utxo(dsv_chain_t *chain,
                                const dsv_hash256_t *txid,
                                uint32_t vout) {
    pthread_rwlock_rdlock(&chain->lock);
    dsv_utxo_t *utxo = dsv_storage_get_utxo(chain->storage, txid, vout);
    pthread_rwlock_unlock(&chain->lock);
    return utxo;
}

dsv_utxo_t **dsv_chain_get_address_utxos(dsv_chain_t *chain,
                                          const dsv_address_t *addr,
                                          size_t *count) {
    pthread_rwlock_rdlock(&chain->lock);
    dsv_utxo_t **utxos = dsv_storage_get_utxos_for_address(chain->storage,
                                                           addr, count);
    pthread_rwlock_unlock(&chain->lock);
    return utxos;
}

int dsv_chain_get_balance(dsv_chain_t *chain,
                           const dsv_address_t *addr,
                           dsv_u320_t *balance) {
    *balance = DSV_U320_ZERO;
    
    size_t count;
    dsv_utxo_t **utxos = dsv_chain_get_address_utxos(chain, addr, &count);
    if (!utxos) return DSV_OK;
    
    for (size_t i = 0; i < count; i++) {
        dsv_u320_add(balance, balance, &utxos[i]->amount);
    }
    
    dsv_utxo_array_free(utxos, count);
    return DSV_OK;
}

/* ==========================================================================
 * Transaction Validation
 * ========================================================================== */

int dsv_chain_validate_tx(dsv_chain_t *chain, const dsv_tx_t *tx,
                           dsv_u320_t *fee) {
    *fee = DSV_U320_ZERO;
    
    /* Basic checks */
    int err = dsv_tx_check_basic(tx);
    if (err != DSV_OK) return err;
    
    /* No coinbase in mempool */
    if (dsv_tx_is_coinbase(tx)) return DSV_ERR_INVALID;
    
    pthread_rwlock_rdlock(&chain->lock);
    
    dsv_u320_t input_sum = DSV_U320_ZERO;
    dsv_u320_t output_sum = DSV_U320_ZERO;
    
    for (uint32_t i = 0; i < tx->input_count; i++) {
        /* Check UTXO exists */
        dsv_utxo_t *utxo = dsv_storage_get_utxo(chain->storage,
            &tx->inputs[i].prev_txid, tx->inputs[i].prev_vout);
        
        if (!utxo) {
            /* Check mempool */
            if (chain->mempool) {
                dsv_tx_t *mempool_tx = dsv_mempool_get(chain->mempool,
                                                        &tx->inputs[i].prev_txid);
                if (mempool_tx && tx->inputs[i].prev_vout < mempool_tx->output_count) {
                    dsv_u320_add(&input_sum, &input_sum,
                                 &mempool_tx->outputs[tx->inputs[i].prev_vout].amount);
                    dsv_tx_free(mempool_tx);
                    continue;
                }
                if (mempool_tx) dsv_tx_free(mempool_tx);
            }
            pthread_rwlock_unlock(&chain->lock);
            return DSV_ERR_NOT_FOUND;
        }
        
        /* Check coinbase maturity */
        if (utxo->is_coinbase) {
            int64_t confirmations = chain->best_height - utxo->height;
            if (confirmations < DSV_COINBASE_MATURITY) {
                dsv_utxo_free(utxo);
                pthread_rwlock_unlock(&chain->lock);
                return DSV_ERR_CONSENSUS;
            }
        }
        
        /* Check not already spent in mempool */
        if (chain->mempool) {
            if (dsv_mempool_is_spent(chain->mempool,
                                      &tx->inputs[i].prev_txid,
                                      tx->inputs[i].prev_vout)) {
                dsv_utxo_free(utxo);
                pthread_rwlock_unlock(&chain->lock);
                return DSV_ERR_DUPLICATE;
            }
        }
        
        /* Verify pubkey matches address */
        dsv_address_t derived_addr;
        dsv_address_from_pubkey(&derived_addr, &tx->inputs[i].pubkey,
                                utxo->address.version);
        if (!dsv_address_eq(&derived_addr, &utxo->address)) {
            dsv_utxo_free(utxo);
            pthread_rwlock_unlock(&chain->lock);
            return DSV_ERR_VERIFY;
        }
        
        dsv_u320_add(&input_sum, &input_sum, &utxo->amount);
        dsv_utxo_free(utxo);
    }
    
    pthread_rwlock_unlock(&chain->lock);
    
    /* Verify signatures */
    err = dsv_tx_verify_signatures(tx);
    if (err != DSV_OK) return err;
    
    /* Calculate outputs sum */
    for (uint32_t i = 0; i < tx->output_count; i++) {
        dsv_u320_add(&output_sum, &output_sum, &tx->outputs[i].amount);
    }
    
    /* Check inputs >= outputs */
    if (dsv_u320_cmp(&input_sum, &output_sum) < 0) {
        return DSV_ERR_CONSENSUS;
    }
    
    /* Calculate fee */
    dsv_u320_sub(fee, &input_sum, &output_sum);
    
    return DSV_OK;
}

bool dsv_chain_are_inputs_available(dsv_chain_t *chain, const dsv_tx_t *tx) {
    pthread_rwlock_rdlock(&chain->lock);
    
    for (uint32_t i = 0; i < tx->input_count; i++) {
        dsv_utxo_t *utxo = dsv_storage_get_utxo(chain->storage,
            &tx->inputs[i].prev_txid, tx->inputs[i].prev_vout);
        if (!utxo) {
            pthread_rwlock_unlock(&chain->lock);
            return false;
        }
        dsv_utxo_free(utxo);
    }
    
    pthread_rwlock_unlock(&chain->lock);
    return true;
}

/* ==========================================================================
 * Mining Support
 * ========================================================================== */

dsv_block_t *dsv_chain_create_block_template(dsv_chain_t *chain,
                                              const dsv_address_t *coinbase_addr) {
    pthread_rwlock_rdlock(&chain->lock);
    
    dsv_block_t *block = dsv_block_new();
    if (!block) {
        pthread_rwlock_unlock(&chain->lock);
        return NULL;
    }
    
    /* Fill header */
    block->header.version = 1;
    block->header.prev_hash = chain->best_hash;
    block->header.timestamp = (uint32_t)time(NULL);
    block->header.bits = dsv_chain_get_current_bits(chain);
    block->header.nonce = 0;
    
    int64_t height = chain->best_height + 1;
    
    /* Create coinbase transaction */
    dsv_tx_t *coinbase = dsv_tx_new();
    if (!coinbase) {
        dsv_block_free(block);
        pthread_rwlock_unlock(&chain->lock);
        return NULL;
    }
    
    coinbase->version = 1;
    coinbase->input_count = 1;
    coinbase->inputs = calloc(1, sizeof(dsv_txin_t));
    coinbase->inputs[0].prev_txid = DSV_HASH_ZERO;
    coinbase->inputs[0].prev_vout = 0xFFFFFFFF;
    
    /* Encode height in coinbase (BIP34) */
    uint8_t height_bytes[8];
    memcpy(height_bytes, &height, sizeof(height));
    memcpy(coinbase->inputs[0].pubkey.data, height_bytes, 8);
    
    coinbase->output_count = 1;
    coinbase->outputs = calloc(1, sizeof(dsv_txout_t));
    coinbase->outputs[0].address = *coinbase_addr;
    
    /* Get reward */
    dsv_u320_t reward;
    dsv_get_block_reward(&reward, height);
    
    /* Get transactions from mempool */
    dsv_u320_t total_fees = DSV_U320_ZERO;
    size_t tx_count = 0;
    dsv_tx_t **mempool_txs = NULL;
    
    if (chain->mempool) {
        size_t max_block_size = DSV_MAX_BLOCK_SIZE - 1000;  /* Reserve space for coinbase */
        mempool_txs = dsv_mempool_get_block_template(chain->mempool,
                                                      max_block_size,
                                                      &total_fees,
                                                      &tx_count);
    }
    
    /* Set coinbase amount */
    dsv_u320_add(&coinbase->outputs[0].amount, &reward, &total_fees);
    
    dsv_block_add_tx(block, coinbase);
    
    /* Add mempool transactions */
    if (mempool_txs) {
        for (size_t i = 0; i < tx_count; i++) {
            dsv_block_add_tx(block, mempool_txs[i]);
        }
        free(mempool_txs);  /* Transactions are now owned by block */
    }
    
    /* Compute merkle root */
    dsv_hash256_t *txids = malloc(block->tx_count * sizeof(dsv_hash256_t));
    if (txids) {
        for (uint32_t i = 0; i < block->tx_count; i++) {
            dsv_tx_compute_txid(&txids[i], block->txs[i]);
        }
        dsv_compute_merkle_root(&block->header.merkle_root, txids, block->tx_count);
        free(txids);
    }
    
    pthread_rwlock_unlock(&chain->lock);
    return block;
}

int dsv_chain_submit_block(dsv_chain_t *chain, dsv_block_t *block) {
    return dsv_chain_accept_block(chain, block);
}

