/**
 * DSV Memory Pool Implementation
 */

#include <pthread.h>
#include "dsv_consensus.h"
#include "dsv_mempool.h"
#include "dsv_serialize.h"
#include "dsv_crypto.h"
#include "dsv_u320.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Hash table bucket */
typedef struct mempool_node_s {
    dsv_mempool_entry_t entry;
    struct mempool_node_s *next;
} mempool_node_t;

/* Spent outpoint tracking */
typedef struct spent_node_s {
    dsv_hash256_t txid;
    uint32_t vout;
    dsv_hash256_t spending_txid;
    struct spent_node_s *next;
} spent_node_t;

#define HASH_TABLE_SIZE 65536
#define SPENT_TABLE_SIZE 65536

struct dsv_mempool_s {
    mempool_node_t *buckets[HASH_TABLE_SIZE];
    spent_node_t *spent_buckets[SPENT_TABLE_SIZE];
    size_t tx_count;
    size_t memory_usage;
    size_t max_size;
    pthread_mutex_t lock;
};

/* Hash function for txid */
static uint32_t hash_txid(const dsv_hash256_t *txid) {
    uint32_t hash = 0;
    for (int i = 0; i < 32; i += 4) {
        hash ^= *(uint32_t *)(txid->data + i);
    }
    return hash % HASH_TABLE_SIZE;
}

/* Hash function for outpoint */
static uint32_t hash_outpoint(const dsv_hash256_t *txid, uint32_t vout) {
    uint32_t hash = vout;
    for (int i = 0; i < 32; i += 4) {
        hash ^= *(uint32_t *)(txid->data + i);
    }
    return hash % SPENT_TABLE_SIZE;
}

dsv_mempool_t *dsv_mempool_new(size_t max_size_mb) {
    dsv_mempool_t *mp = calloc(1, sizeof(dsv_mempool_t));
    if (!mp) return NULL;
    
    mp->max_size = max_size_mb * 1024 * 1024;
    pthread_mutex_init(&mp->lock, NULL);
    
    return mp;
}

void dsv_mempool_free(dsv_mempool_t *mp) {
    if (!mp) return;
    
    dsv_mempool_clear(mp);
    pthread_mutex_destroy(&mp->lock);
    free(mp);
}

int dsv_mempool_add(dsv_mempool_t *mp, dsv_tx_t *tx, const dsv_u320_t *fee) {
    pthread_mutex_lock(&mp->lock);
    
    /* Compute txid */
    dsv_hash256_t txid;
    dsv_tx_compute_txid(&txid, tx);
    
    /* Check if already exists */
    uint32_t bucket = hash_txid(&txid);
    mempool_node_t *node = mp->buckets[bucket];
    while (node) {
        if (dsv_hash_eq(&node->entry.tx->txid, &txid)) {
            pthread_mutex_unlock(&mp->lock);
            return DSV_ERR_DUPLICATE;
        }
        node = node->next;
    }
    
    /* Check for double-spend against mempool */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        uint32_t spent_bucket = hash_outpoint(&tx->inputs[i].prev_txid,
                                               tx->inputs[i].prev_vout);
        spent_node_t *spent = mp->spent_buckets[spent_bucket];
        while (spent) {
            if (dsv_hash_eq(&spent->txid, &tx->inputs[i].prev_txid) &&
                spent->vout == tx->inputs[i].prev_vout) {
                pthread_mutex_unlock(&mp->lock);
                return DSV_ERR_DUPLICATE;  /* Double spend */
            }
            spent = spent->next;
        }
    }
    
    /* Calculate tx size */
    size_t tx_size = dsv_tx_serialized_size(tx);
    
    /* Check memory limit */
    if (mp->memory_usage + tx_size + sizeof(mempool_node_t) > mp->max_size) {
        pthread_mutex_unlock(&mp->lock);
        return DSV_ERR_LIMIT;
    }
    
    /* Create entry */
    node = calloc(1, sizeof(mempool_node_t));
    if (!node) {
        pthread_mutex_unlock(&mp->lock);
        return DSV_ERR_NOMEM;
    }
    
    node->entry.tx = dsv_tx_copy(tx);
    if (!node->entry.tx) {
        free(node);
        pthread_mutex_unlock(&mp->lock);
        return DSV_ERR_NOMEM;
    }
    
    node->entry.tx->txid = txid;
    node->entry.tx->txid_computed = true;
    dsv_u320_copy(&node->entry.fee, fee);
    node->entry.tx_size = tx_size;
    node->entry.time_added = time(NULL);
    
    /* Calculate fee per byte */
    uint64_t fee_u64;
    dsv_u320_t fee_copy;
    dsv_u320_copy(&fee_copy, fee);
    dsv_u320_div_u64(&fee_copy, &fee_u64, &fee_copy, tx_size);
    node->entry.fee_per_byte = fee_u64;
    
    /* Add to hash table */
    node->next = mp->buckets[bucket];
    mp->buckets[bucket] = node;
    
    /* Track spent outpoints */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        spent_node_t *spent = calloc(1, sizeof(spent_node_t));
        if (spent) {
            spent->txid = tx->inputs[i].prev_txid;
            spent->vout = tx->inputs[i].prev_vout;
            spent->spending_txid = txid;
            
            uint32_t spent_bucket = hash_outpoint(&spent->txid, spent->vout);
            spent->next = mp->spent_buckets[spent_bucket];
            mp->spent_buckets[spent_bucket] = spent;
        }
    }
    
    mp->tx_count++;
    mp->memory_usage += tx_size + sizeof(mempool_node_t);
    
    pthread_mutex_unlock(&mp->lock);
    return DSV_OK;
}

void dsv_mempool_remove(dsv_mempool_t *mp, const dsv_hash256_t *txid) {
    pthread_mutex_lock(&mp->lock);
    
    uint32_t bucket = hash_txid(txid);
    mempool_node_t **prev = &mp->buckets[bucket];
    mempool_node_t *node = *prev;
    
    while (node) {
        if (dsv_hash_eq(&node->entry.tx->txid, txid)) {
            /* Remove spent outpoint tracking */
            for (uint32_t i = 0; i < node->entry.tx->input_count; i++) {
                uint32_t spent_bucket = hash_outpoint(
                    &node->entry.tx->inputs[i].prev_txid,
                    node->entry.tx->inputs[i].prev_vout);
                
                spent_node_t **spent_prev = &mp->spent_buckets[spent_bucket];
                spent_node_t *spent = *spent_prev;
                
                while (spent) {
                    if (dsv_hash_eq(&spent->txid, &node->entry.tx->inputs[i].prev_txid) &&
                        spent->vout == node->entry.tx->inputs[i].prev_vout) {
                        *spent_prev = spent->next;
                        free(spent);
                        break;
                    }
                    spent_prev = &spent->next;
                    spent = *spent_prev;
                }
            }
            
            *prev = node->next;
            mp->memory_usage -= node->entry.tx_size + sizeof(mempool_node_t);
            mp->tx_count--;
            dsv_tx_free(node->entry.tx);
            free(node);
            break;
        }
        prev = &node->next;
        node = *prev;
    }
    
    pthread_mutex_unlock(&mp->lock);
}

void dsv_mempool_remove_for_block(dsv_mempool_t *mp, const dsv_block_t *block) {
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_hash256_t txid;
        dsv_tx_compute_txid(&txid, block->txs[i]);
        dsv_mempool_remove(mp, &txid);
    }
}

void dsv_mempool_reorg_add(dsv_mempool_t *mp, dsv_tx_t **txs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        /* Skip coinbase */
        if (dsv_tx_is_coinbase(txs[i])) continue;
        
        /* Try to add back - may fail if inputs are spent */
        dsv_u320_t zero = DSV_U320_ZERO;
        dsv_mempool_add(mp, txs[i], &zero);
    }
}

bool dsv_mempool_contains(dsv_mempool_t *mp, const dsv_hash256_t *txid) {
    pthread_mutex_lock(&mp->lock);
    
    uint32_t bucket = hash_txid(txid);
    mempool_node_t *node = mp->buckets[bucket];
    
    while (node) {
        if (dsv_hash_eq(&node->entry.tx->txid, txid)) {
            pthread_mutex_unlock(&mp->lock);
            return true;
        }
        node = node->next;
    }
    
    pthread_mutex_unlock(&mp->lock);
    return false;
}

dsv_tx_t *dsv_mempool_get(dsv_mempool_t *mp, const dsv_hash256_t *txid) {
    pthread_mutex_lock(&mp->lock);
    
    uint32_t bucket = hash_txid(txid);
    mempool_node_t *node = mp->buckets[bucket];
    
    while (node) {
        if (dsv_hash_eq(&node->entry.tx->txid, txid)) {
            dsv_tx_t *tx = dsv_tx_copy(node->entry.tx);
            pthread_mutex_unlock(&mp->lock);
            return tx;
        }
        node = node->next;
    }
    
    pthread_mutex_unlock(&mp->lock);
    return NULL;
}

dsv_mempool_entry_t *dsv_mempool_get_entry(dsv_mempool_t *mp,
                                            const dsv_hash256_t *txid) {
    pthread_mutex_lock(&mp->lock);
    
    uint32_t bucket = hash_txid(txid);
    mempool_node_t *node = mp->buckets[bucket];
    
    while (node) {
        if (dsv_hash_eq(&node->entry.tx->txid, txid)) {
            dsv_mempool_entry_t *entry = malloc(sizeof(dsv_mempool_entry_t));
            if (entry) {
                entry->tx = dsv_tx_copy(node->entry.tx);
                dsv_u320_copy(&entry->fee, &node->entry.fee);
                entry->fee_per_byte = node->entry.fee_per_byte;
                entry->time_added = node->entry.time_added;
                entry->tx_size = node->entry.tx_size;
            }
            pthread_mutex_unlock(&mp->lock);
            return entry;
        }
        node = node->next;
    }
    
    pthread_mutex_unlock(&mp->lock);
    return NULL;
}

/* Comparison function for sorting by fee rate */
static int compare_by_fee_rate(const void *a, const void *b) {
    const mempool_node_t *na = *(const mempool_node_t **)a;
    const mempool_node_t *nb = *(const mempool_node_t **)b;
    
    if (na->entry.fee_per_byte > nb->entry.fee_per_byte) return -1;
    if (na->entry.fee_per_byte < nb->entry.fee_per_byte) return 1;
    return 0;
}

dsv_tx_t **dsv_mempool_get_block_template(dsv_mempool_t *mp,
                                           size_t max_size,
                                           dsv_u320_t *total_fees,
                                           size_t *count) {
    pthread_mutex_lock(&mp->lock);
    
    *count = 0;
    *total_fees = DSV_U320_ZERO;
    
    if (mp->tx_count == 0) {
        pthread_mutex_unlock(&mp->lock);
        return NULL;
    }
    
    /* Collect all entries */
    mempool_node_t **sorted = malloc(mp->tx_count * sizeof(mempool_node_t *));
    if (!sorted) {
        pthread_mutex_unlock(&mp->lock);
        return NULL;
    }
    
    size_t idx = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        mempool_node_t *node = mp->buckets[i];
        while (node) {
            sorted[idx++] = node;
            node = node->next;
        }
    }
    
    /* Sort by fee rate (highest first) */
    qsort(sorted, idx, sizeof(mempool_node_t *), compare_by_fee_rate);
    
    /* Select transactions */
    dsv_tx_t **txs = malloc(idx * sizeof(dsv_tx_t *));
    if (!txs) {
        free(sorted);
        pthread_mutex_unlock(&mp->lock);
        return NULL;
    }
    
    size_t current_size = 0;
    for (size_t i = 0; i < idx; i++) {
        if (current_size + sorted[i]->entry.tx_size > max_size) continue;
        
        txs[*count] = dsv_tx_copy(sorted[i]->entry.tx);
        if (txs[*count]) {
            dsv_u320_add(total_fees, total_fees, &sorted[i]->entry.fee);
            current_size += sorted[i]->entry.tx_size;
            (*count)++;
        }
    }
    
    free(sorted);
    pthread_mutex_unlock(&mp->lock);
    
    return txs;
}

size_t dsv_mempool_size(dsv_mempool_t *mp) {
    pthread_mutex_lock(&mp->lock);
    size_t count = mp->tx_count;
    pthread_mutex_unlock(&mp->lock);
    return count;
}

size_t dsv_mempool_memory_usage(dsv_mempool_t *mp) {
    pthread_mutex_lock(&mp->lock);
    size_t usage = mp->memory_usage;
    pthread_mutex_unlock(&mp->lock);
    return usage;
}

void dsv_mempool_clear(dsv_mempool_t *mp) {
    pthread_mutex_lock(&mp->lock);
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        mempool_node_t *node = mp->buckets[i];
        while (node) {
            mempool_node_t *next = node->next;
            dsv_tx_free(node->entry.tx);
            free(node);
            node = next;
        }
        mp->buckets[i] = NULL;
    }
    
    for (int i = 0; i < SPENT_TABLE_SIZE; i++) {
        spent_node_t *spent = mp->spent_buckets[i];
        while (spent) {
            spent_node_t *next = spent->next;
            free(spent);
            spent = next;
        }
        mp->spent_buckets[i] = NULL;
    }
    
    mp->tx_count = 0;
    mp->memory_usage = 0;
    
    pthread_mutex_unlock(&mp->lock);
}

bool dsv_mempool_is_spent(dsv_mempool_t *mp,
                          const dsv_hash256_t *txid,
                          uint32_t vout) {
    pthread_mutex_lock(&mp->lock);
    
    uint32_t bucket = hash_outpoint(txid, vout);
    spent_node_t *spent = mp->spent_buckets[bucket];
    
    while (spent) {
        if (dsv_hash_eq(&spent->txid, txid) && spent->vout == vout) {
            pthread_mutex_unlock(&mp->lock);
            return true;
        }
        spent = spent->next;
    }
    
    pthread_mutex_unlock(&mp->lock);
    return false;
}

void dsv_mempool_entry_free(dsv_mempool_entry_t *entry) {
    if (!entry) return;
    dsv_tx_free(entry->tx);
    free(entry);
}

