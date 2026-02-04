/**
 * DSV Storage Layer Implementation
 * 
 * Uses LevelDB for key-value storage.
 */

#include "dsv_storage.h"
#include "dsv_serialize.h"
#include "dsv_crypto.h"
#include "dsv_u320.h"
#include <leveldb/c.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

/* Key prefixes for different data types */
#define PREFIX_BLOCK_INDEX      'b'
#define PREFIX_BLOCK_HEIGHT     'h'
#define PREFIX_UTXO             'u'
#define PREFIX_ADDR_UTXO        'a'
#define PREFIX_UNDO             'd'
#define PREFIX_META             'm'

#define KEY_BEST_BLOCK          "m:best"
#define KEY_PRUNE_HEIGHT        "m:prune"

/* Block file constants */
#define BLOCK_FILE_MAX_SIZE     (128 * 1024 * 1024)  /* 128 MB per file */
#define BLOCK_MAGIC             0x44535642  /* "DSVB" */

struct dsv_storage_s {
    leveldb_t *db;
    leveldb_options_t *options;
    leveldb_readoptions_t *read_opts;
    leveldb_writeoptions_t *write_opts;
    char *path;
    bool prune_enabled;
    uint64_t prune_target_mb;
};

struct dsv_blockfile_s {
    char *dir;
    uint64_t current_file_no;
    uint64_t current_offset;
    FILE *current_file;
};

struct dsv_write_batch_s {
    leveldb_writebatch_t *batch;
};

/* ==========================================================================
 * Helper Functions
 * ========================================================================== */

static void make_block_index_key(char *key, const dsv_hash256_t *hash) {
    key[0] = PREFIX_BLOCK_INDEX;
    key[1] = ':';
    memcpy(key + 2, hash->data, 32);
}

static void make_height_key(char *key, int64_t height) {
    key[0] = PREFIX_BLOCK_HEIGHT;
    key[1] = ':';
    memcpy(key + 2, &height, sizeof(height));
}

static void make_utxo_key(char *key, const dsv_hash256_t *txid, uint32_t vout) {
    key[0] = PREFIX_UTXO;
    key[1] = ':';
    memcpy(key + 2, txid->data, 32);
    memcpy(key + 34, &vout, 4);
}

static void make_addr_utxo_key(char *key, const dsv_address_t *addr,
                               const dsv_hash256_t *txid, uint32_t vout) {
    key[0] = PREFIX_ADDR_UTXO;
    key[1] = ':';
    key[2] = addr->version;
    memcpy(key + 3, addr->hash, 20);
    memcpy(key + 23, txid->data, 32);
    memcpy(key + 55, &vout, 4);
}

static void make_undo_key(char *key, const dsv_hash256_t *hash) {
    key[0] = PREFIX_UNDO;
    key[1] = ':';
    memcpy(key + 2, hash->data, 32);
}

/* ==========================================================================
 * Database Initialization
 * ========================================================================== */

dsv_storage_t *dsv_storage_open(const char *path) {
    dsv_storage_t *storage = calloc(1, sizeof(dsv_storage_t));
    if (!storage) return NULL;
    
    storage->path = strdup(path);
    if (!storage->path) {
        free(storage);
        return NULL;
    }
    
    /* Create directory if needed */
    #ifdef _WIN32
    mkdir(path);
#else
    mkdir(path, 0755);
#endif

    
    storage->options = leveldb_options_create();
    leveldb_options_set_create_if_missing(storage->options, 1);
    leveldb_options_set_write_buffer_size(storage->options, 64 * 1024 * 1024);
    leveldb_options_set_max_open_files(storage->options, 500);
    leveldb_options_set_compression(storage->options, leveldb_snappy_compression);
    
    char *err = NULL;
    storage->db = leveldb_open(storage->options, path, &err);
    if (err) {
        fprintf(stderr, "Failed to open database: %s\n", err);
        leveldb_free(err);
        leveldb_options_destroy(storage->options);
        free(storage->path);
        free(storage);
        return NULL;
    }
    
    storage->read_opts = leveldb_readoptions_create();
    storage->write_opts = leveldb_writeoptions_create();
    leveldb_writeoptions_set_sync(storage->write_opts, 0);  /* Async for performance */
    
    return storage;
}

void dsv_storage_close(dsv_storage_t *storage) {
    if (!storage) return;
    
    if (storage->db) leveldb_close(storage->db);
    if (storage->options) leveldb_options_destroy(storage->options);
    if (storage->read_opts) leveldb_readoptions_destroy(storage->read_opts);
    if (storage->write_opts) leveldb_writeoptions_destroy(storage->write_opts);
    free(storage->path);
    free(storage);
}

/* ==========================================================================
 * Block Index Database
 * ========================================================================== */

int dsv_storage_put_block_index(dsv_storage_t *storage,
                                 const dsv_block_index_t *index) {
    char key[64];
    make_block_index_key(key, &index->hash);
    
    /* Serialize index */
    dsv_buffer_t *buf = dsv_buffer_new(256);
    if (!buf) return DSV_ERR_NOMEM;
    
    dsv_write_hash(buf, &index->prev_hash);
    dsv_write_u64(buf, (uint64_t)index->height);
    dsv_write_u32(buf, index->timestamp);
    dsv_write_u32(buf, index->bits);
    dsv_write_u32(buf, index->nonce);
    dsv_write_bytes(buf, index->chainwork.data, 32);
    dsv_write_u64(buf, index->file_no);
    dsv_write_u64(buf, index->file_offset);
    dsv_write_u32(buf, index->tx_count);
    dsv_write_u8(buf, index->on_main_chain ? 1 : 0);
    
    char *err = NULL;
    leveldb_put(storage->db, storage->write_opts, key, 34,
                (const char *)buf->data, buf->pos, &err);
    dsv_buffer_free(buf);
    
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    /* Also index by height if on main chain */
    if (index->on_main_chain) {
        char height_key[16];
        make_height_key(height_key, index->height);
        leveldb_put(storage->db, storage->write_opts, height_key, 10,
                    (const char *)index->hash.data, 32, &err);
        if (err) {
            leveldb_free(err);
            return DSV_ERR_DATABASE;
        }
    }
    
    return DSV_OK;
}

dsv_block_index_t *dsv_storage_get_block_index(dsv_storage_t *storage,
                                                const dsv_hash256_t *hash) {
    char key[64];
    make_block_index_key(key, hash);
    
    size_t value_len;
    char *err = NULL;
    char *value = leveldb_get(storage->db, storage->read_opts, key, 34,
                              &value_len, &err);
    if (err || !value) {
        if (err) leveldb_free(err);
        return NULL;
    }
    
    dsv_block_index_t *index = calloc(1, sizeof(dsv_block_index_t));
    if (!index) {
        leveldb_free(value);
        return NULL;
    }
    
    dsv_buffer_t *buf = dsv_buffer_from_data((uint8_t *)value, value_len);
    if (!buf) {
        leveldb_free(value);
        free(index);
        return NULL;
    }
    
    index->hash = *hash;
    dsv_read_hash(buf, &index->prev_hash);
    uint64_t height;
    dsv_read_u64(buf, &height);
    index->height = (int64_t)height;
    dsv_read_u32(buf, &index->timestamp);
    dsv_read_u32(buf, &index->bits);
    dsv_read_u32(buf, &index->nonce);
    dsv_read_bytes(buf, index->chainwork.data, 32);
    dsv_read_u64(buf, &index->file_no);
    dsv_read_u64(buf, &index->file_offset);
    dsv_read_u32(buf, &index->tx_count);
    uint8_t on_main;
    dsv_read_u8(buf, &on_main);
    index->on_main_chain = on_main != 0;
    
    dsv_buffer_free(buf);
    leveldb_free(value);
    
    return index;
}

dsv_block_index_t *dsv_storage_get_block_at_height(dsv_storage_t *storage,
                                                    int64_t height) {
    char key[16];
    make_height_key(key, height);
    
    size_t value_len;
    char *err = NULL;
    char *value = leveldb_get(storage->db, storage->read_opts, key, 10,
                              &value_len, &err);
    if (err || !value || value_len != 32) {
        if (err) leveldb_free(err);
        if (value) leveldb_free(value);
        return NULL;
    }
    
    dsv_hash256_t hash;
    memcpy(hash.data, value, 32);
    leveldb_free(value);
    
    return dsv_storage_get_block_index(storage, &hash);
}

int dsv_storage_put_best_block(dsv_storage_t *storage,
                                const dsv_hash256_t *hash) {
    char *err = NULL;
    leveldb_put(storage->db, storage->write_opts, KEY_BEST_BLOCK,
                strlen(KEY_BEST_BLOCK), (const char *)hash->data, 32, &err);
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    return DSV_OK;
}

int dsv_storage_get_best_block(dsv_storage_t *storage, dsv_hash256_t *hash) {
    size_t value_len;
    char *err = NULL;
    char *value = leveldb_get(storage->db, storage->read_opts, KEY_BEST_BLOCK,
                              strlen(KEY_BEST_BLOCK), &value_len, &err);
    if (err || !value || value_len != 32) {
        if (err) leveldb_free(err);
        if (value) leveldb_free(value);
        return DSV_ERR_NOT_FOUND;
    }
    
    memcpy(hash->data, value, 32);
    leveldb_free(value);
    return DSV_OK;
}

void dsv_block_index_free(dsv_block_index_t *index) {
    free(index);
}

/* ==========================================================================
 * UTXO Database
 * ========================================================================== */

int dsv_storage_put_utxo(dsv_storage_t *storage, const dsv_utxo_t *utxo) {
    char key[64];
    make_utxo_key(key, &utxo->txid, utxo->vout);
    
    /* Serialize UTXO */
    dsv_buffer_t *buf = dsv_buffer_new(128);
    if (!buf) return DSV_ERR_NOMEM;
    
    dsv_write_u320(buf, &utxo->amount);
    dsv_write_u8(buf, utxo->address.version);
    dsv_write_bytes(buf, utxo->address.hash, 20);
    dsv_write_u64(buf, (uint64_t)utxo->height);
    dsv_write_u8(buf, utxo->is_coinbase ? 1 : 0);
    
    char *err = NULL;
    leveldb_put(storage->db, storage->write_opts, key, 38,
                (const char *)buf->data, buf->pos, &err);
    dsv_buffer_free(buf);
    
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    /* Also index by address */
    char addr_key[64];
    make_addr_utxo_key(addr_key, &utxo->address, &utxo->txid, utxo->vout);
    leveldb_put(storage->db, storage->write_opts, addr_key, 59, "", 0, &err);
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    return DSV_OK;
}

dsv_utxo_t *dsv_storage_get_utxo(dsv_storage_t *storage,
                                  const dsv_hash256_t *txid,
                                  uint32_t vout) {
    char key[64];
    make_utxo_key(key, txid, vout);
    
    size_t value_len;
    char *err = NULL;
    char *value = leveldb_get(storage->db, storage->read_opts, key, 38,
                              &value_len, &err);
    if (err || !value) {
        if (err) leveldb_free(err);
        return NULL;
    }
    
    dsv_utxo_t *utxo = calloc(1, sizeof(dsv_utxo_t));
    if (!utxo) {
        leveldb_free(value);
        return NULL;
    }
    
    dsv_buffer_t *buf = dsv_buffer_from_data((uint8_t *)value, value_len);
    if (!buf) {
        leveldb_free(value);
        free(utxo);
        return NULL;
    }
    
    utxo->txid = *txid;
    utxo->vout = vout;
    dsv_read_u320(buf, &utxo->amount);
    dsv_read_u8(buf, &utxo->address.version);
    dsv_read_bytes(buf, utxo->address.hash, 20);
    uint64_t height;
    dsv_read_u64(buf, &height);
    utxo->height = (int64_t)height;
    uint8_t is_coinbase;
    dsv_read_u8(buf, &is_coinbase);
    utxo->is_coinbase = is_coinbase != 0;
    
    dsv_buffer_free(buf);
    leveldb_free(value);
    
    return utxo;
}

int dsv_storage_delete_utxo(dsv_storage_t *storage,
                             const dsv_hash256_t *txid,
                             uint32_t vout) {
    /* First get the UTXO to find the address for index deletion */
    dsv_utxo_t *utxo = dsv_storage_get_utxo(storage, txid, vout);
    if (!utxo) return DSV_ERR_NOT_FOUND;
    
    char *err = NULL;
    
    /* Delete address index */
    char addr_key[64];
    make_addr_utxo_key(addr_key, &utxo->address, txid, vout);
    leveldb_delete(storage->db, storage->write_opts, addr_key, 59, &err);
    dsv_utxo_free(utxo);
    
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    /* Delete main UTXO entry */
    char key[64];
    make_utxo_key(key, txid, vout);
    leveldb_delete(storage->db, storage->write_opts, key, 38, &err);
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    return DSV_OK;
}

dsv_utxo_t **dsv_storage_get_utxos_for_address(dsv_storage_t *storage,
                                                const dsv_address_t *addr,
                                                size_t *count) {
    *count = 0;
    
    /* Build prefix for address UTXOs */
    char prefix[32];
    prefix[0] = PREFIX_ADDR_UTXO;
    prefix[1] = ':';
    prefix[2] = addr->version;
    memcpy(prefix + 3, addr->hash, 20);
    
    leveldb_iterator_t *iter = leveldb_create_iterator(storage->db, storage->read_opts);
    leveldb_iter_seek(iter, prefix, 23);
    
    /* First pass: count UTXOs */
    size_t capacity = 16;
    dsv_utxo_t **utxos = malloc(capacity * sizeof(dsv_utxo_t *));
    if (!utxos) {
        leveldb_iter_destroy(iter);
        return NULL;
    }
    
    while (leveldb_iter_valid(iter)) {
        size_t key_len;
        const char *key = leveldb_iter_key(iter, &key_len);
        
        /* Check prefix match */
        if (key_len < 23 || memcmp(key, prefix, 23) != 0) break;
        
        /* Extract txid and vout from key */
        dsv_hash256_t txid;
        uint32_t vout;
        memcpy(txid.data, key + 23, 32);
        memcpy(&vout, key + 55, 4);
        
        dsv_utxo_t *utxo = dsv_storage_get_utxo(storage, &txid, vout);
        if (utxo) {
            if (*count >= capacity) {
                capacity *= 2;
                dsv_utxo_t **new_utxos = realloc(utxos, capacity * sizeof(dsv_utxo_t *));
                if (!new_utxos) {
                    dsv_utxo_array_free(utxos, *count);
                    leveldb_iter_destroy(iter);
                    return NULL;
                }
                utxos = new_utxos;
            }
            utxos[(*count)++] = utxo;
        }
        
        leveldb_iter_next(iter);
    }
    
    leveldb_iter_destroy(iter);
    return utxos;
}

void dsv_utxo_free(dsv_utxo_t *utxo) {
    free(utxo);
}

void dsv_utxo_array_free(dsv_utxo_t **utxos, size_t count) {
    if (!utxos) return;
    for (size_t i = 0; i < count; i++) {
        dsv_utxo_free(utxos[i]);
    }
    free(utxos);
}

/* ==========================================================================
 * Block Files
 * ========================================================================== */

dsv_blockfile_t *dsv_blockfile_open(const char *dir) {
    dsv_blockfile_t *bf = calloc(1, sizeof(dsv_blockfile_t));
    if (!bf) return NULL;
    
    bf->dir = strdup(dir);
    if (!bf->dir) {
        free(bf);
        return NULL;
    }
    
    #ifdef _WIN32
    mkdir(dir);
#else
    mkdir(dir, 0755);
#endif

    
    /* Find current file */
    for (bf->current_file_no = 0; ; bf->current_file_no++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/blk%05llu.dat", 
                 bf->dir, (unsigned long long)bf->current_file_no);
        
        struct stat st;
        if (stat(path, &st) != 0) {
            if (bf->current_file_no > 0) {
                bf->current_file_no--;
                snprintf(path, sizeof(path), "%s/blk%05llu.dat",
                         bf->dir, (unsigned long long)bf->current_file_no);
                stat(path, &st);
                bf->current_offset = st.st_size;
            }
            break;
        }
        
        if (st.st_size < BLOCK_FILE_MAX_SIZE) {
            bf->current_offset = st.st_size;
            break;
        }
    }
    
    return bf;
}

void dsv_blockfile_close(dsv_blockfile_t *bf) {
    if (!bf) return;
    if (bf->current_file) fclose(bf->current_file);
    free(bf->dir);
    free(bf);
}

int dsv_blockfile_write_block(dsv_blockfile_t *bf,
                               const dsv_block_t *block,
                               uint64_t *file_no,
                               uint64_t *file_offset) {
    /* Serialize block */
    dsv_buffer_t *buf = dsv_buffer_new(DSV_MAX_BLOCK_SIZE);
    if (!buf) return DSV_ERR_NOMEM;
    
    if (!dsv_block_serialize(buf, block)) {
        dsv_buffer_free(buf);
        return DSV_ERR_VERIFY;

    }
    
    /* Check if need new file */
    if (bf->current_offset + buf->pos + 8 > BLOCK_FILE_MAX_SIZE) {
        if (bf->current_file) {
            fclose(bf->current_file);
            bf->current_file = NULL;
        }
        bf->current_file_no++;
        bf->current_offset = 0;
    }
    
    /* Open file if needed */
    if (!bf->current_file) {
        char path[512];
        snprintf(path, sizeof(path), "%s/blk%05llu.dat",
                 bf->dir, (unsigned long long)bf->current_file_no);
        bf->current_file = fopen(path, "ab+");
        if (!bf->current_file) {
            dsv_buffer_free(buf);
            return DSV_ERR_IO;
        }
    }
    
    *file_no = bf->current_file_no;
    *file_offset = bf->current_offset;
    
    /* Write magic + size + block */
    uint32_t magic = BLOCK_MAGIC;
    uint32_t size = (uint32_t)buf->pos;
    
    fseek(bf->current_file, 0, SEEK_END);
    if (fwrite(&magic, 4, 1, bf->current_file) != 1 ||
        fwrite(&size, 4, 1, bf->current_file) != 1 ||
        fwrite(buf->data, 1, buf->pos, bf->current_file) != buf->pos) {
        dsv_buffer_free(buf);
        return DSV_ERR_IO;
    }
    
    fflush(bf->current_file);
    bf->current_offset += 8 + buf->pos;
    
    dsv_buffer_free(buf);
    return DSV_OK;
}

dsv_block_t *dsv_blockfile_read_block(dsv_blockfile_t *bf,
                                       uint64_t file_no,
                                       uint64_t file_offset) {
    char path[512];
    snprintf(path, sizeof(path), "%s/blk%05llu.dat",
             bf->dir, (unsigned long long)file_no);
    
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, (long)file_offset, SEEK_SET);
    
    uint32_t magic, size;
    if (fread(&magic, 4, 1, f) != 1 || fread(&size, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    
    if (magic != BLOCK_MAGIC || size > DSV_MAX_BLOCK_SIZE) {
        fclose(f);
        return NULL;
    }
    
    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return NULL;
    }
    
    if (fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    
    dsv_buffer_t *buf = dsv_buffer_from_data(data, size);
    if (!buf) {
        free(data);
        return NULL;
    }
    
    dsv_block_t *block = dsv_block_deserialize(buf);
    dsv_buffer_free(buf);
    free(data);
    
    return block;
}

/* ==========================================================================
 * Undo Data
 * ========================================================================== */

int dsv_storage_put_undo(dsv_storage_t *storage, const dsv_undo_data_t *undo) {
    char key[64];
    make_undo_key(key, &undo->block_hash);
    
    dsv_buffer_t *buf = dsv_buffer_new(1024);
    if (!buf) return DSV_ERR_NOMEM;
    
    dsv_write_varint(buf, undo->spent_count);
    for (size_t i = 0; i < undo->spent_count; i++) {
        const dsv_utxo_t *utxo = &undo->spent_utxos[i];
        dsv_write_hash(buf, &utxo->txid);
        dsv_write_u32(buf, utxo->vout);
        dsv_write_u320(buf, &utxo->amount);
        dsv_write_u8(buf, utxo->address.version);
        dsv_write_bytes(buf, utxo->address.hash, 20);
        dsv_write_u64(buf, (uint64_t)utxo->height);
        dsv_write_u8(buf, utxo->is_coinbase ? 1 : 0);
    }
    
    char *err = NULL;
    leveldb_put(storage->db, storage->write_opts, key, 34,
                (const char *)buf->data, buf->pos, &err);
    dsv_buffer_free(buf);
    
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    return DSV_OK;
}

dsv_undo_data_t *dsv_storage_get_undo(dsv_storage_t *storage,
                                       const dsv_hash256_t *block_hash) {
    char key[64];
    make_undo_key(key, block_hash);
    
    size_t value_len;
    char *err = NULL;
    char *value = leveldb_get(storage->db, storage->read_opts, key, 34,
                              &value_len, &err);
    if (err || !value) {
        if (err) leveldb_free(err);
        return NULL;
    }
    
    dsv_undo_data_t *undo = calloc(1, sizeof(dsv_undo_data_t));
    if (!undo) {
        leveldb_free(value);
        return NULL;
    }
    
    undo->block_hash = *block_hash;
    
    dsv_buffer_t *buf = dsv_buffer_from_data((uint8_t *)value, value_len);
    if (!buf) {
        leveldb_free(value);
        free(undo);
        return NULL;
    }
    
    uint64_t spent_count;
    dsv_read_varint(buf, &spent_count);
    undo->spent_count = (size_t)spent_count;
    
    if (undo->spent_count > 0) {
        undo->spent_utxos = calloc(undo->spent_count, sizeof(dsv_utxo_t));
        if (!undo->spent_utxos) {
            dsv_buffer_free(buf);
            leveldb_free(value);
            free(undo);
            return NULL;
        }
        
        for (size_t i = 0; i < undo->spent_count; i++) {
            dsv_utxo_t *utxo = &undo->spent_utxos[i];
            dsv_read_hash(buf, &utxo->txid);
            dsv_read_u32(buf, &utxo->vout);
            dsv_read_u320(buf, &utxo->amount);
            dsv_read_u8(buf, &utxo->address.version);
            dsv_read_bytes(buf, utxo->address.hash, 20);
            uint64_t height;
            dsv_read_u64(buf, &height);
            utxo->height = (int64_t)height;
            uint8_t is_coinbase;
            dsv_read_u8(buf, &is_coinbase);
            utxo->is_coinbase = is_coinbase != 0;
        }
    }
    
    dsv_buffer_free(buf);
    leveldb_free(value);
    
    return undo;
}

int dsv_storage_delete_undo(dsv_storage_t *storage,
                             const dsv_hash256_t *block_hash) {
    char key[64];
    make_undo_key(key, block_hash);
    
    char *err = NULL;
    leveldb_delete(storage->db, storage->write_opts, key, 34, &err);
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    
    return DSV_OK;
}

void dsv_undo_data_free(dsv_undo_data_t *undo) {
    if (!undo) return;
    free(undo->spent_utxos);
    free(undo);
}

/* ==========================================================================
 * Batch Operations
 * ========================================================================== */

dsv_write_batch_t *dsv_write_batch_new(void) {
    dsv_write_batch_t *batch = malloc(sizeof(dsv_write_batch_t));
    if (!batch) return NULL;
    
    batch->batch = leveldb_writebatch_create();
    if (!batch->batch) {
        free(batch);
        return NULL;
    }
    
    return batch;
}

int dsv_write_batch_put_utxo(dsv_write_batch_t *batch, const dsv_utxo_t *utxo) {
    char key[64];
    make_utxo_key(key, &utxo->txid, utxo->vout);
    
    dsv_buffer_t *buf = dsv_buffer_new(128);
    if (!buf) return DSV_ERR_NOMEM;
    
    dsv_write_u320(buf, &utxo->amount);
    dsv_write_u8(buf, utxo->address.version);
    dsv_write_bytes(buf, utxo->address.hash, 20);
    dsv_write_u64(buf, (uint64_t)utxo->height);
    dsv_write_u8(buf, utxo->is_coinbase ? 1 : 0);
    
    leveldb_writebatch_put(batch->batch, key, 38, (const char *)buf->data, buf->pos);
    dsv_buffer_free(buf);
    
    /* Address index */
    char addr_key[64];
    make_addr_utxo_key(addr_key, &utxo->address, &utxo->txid, utxo->vout);
    leveldb_writebatch_put(batch->batch, addr_key, 59, "", 0);
    
    return DSV_OK;
}

int dsv_write_batch_delete_utxo(dsv_write_batch_t *batch,
                                 const dsv_hash256_t *txid,
                                 uint32_t vout) {
    char key[64];
    make_utxo_key(key, txid, vout);
    leveldb_writebatch_delete(batch->batch, key, 38);
    return DSV_OK;
}

int dsv_write_batch_execute(dsv_storage_t *storage, dsv_write_batch_t *batch) {
    char *err = NULL;
    leveldb_write(storage->db, storage->write_opts, batch->batch, &err);
    if (err) {
        leveldb_free(err);
        return DSV_ERR_DATABASE;
    }
    return DSV_OK;
}

void dsv_write_batch_free(dsv_write_batch_t *batch) {
    if (!batch) return;
    leveldb_writebatch_destroy(batch->batch);
    free(batch);
}

/* ==========================================================================
 * Pruning
 * ========================================================================== */

void dsv_storage_set_prune_mode(dsv_storage_t *storage, bool enabled,
                                 uint64_t target_size_mb) {
    storage->prune_enabled = enabled;
    storage->prune_target_mb = target_size_mb;
}

bool dsv_storage_can_prune_block(dsv_storage_t *storage, int64_t height) {
    if (!storage->prune_enabled) return false;
    
    /* Get current best height */
    dsv_hash256_t best_hash;
    if (dsv_storage_get_best_block(storage, &best_hash) != DSV_OK) {
        return false;
    }
    
    dsv_block_index_t *best = dsv_storage_get_block_index(storage, &best_hash);
    if (!best) return false;
    
    /* Keep last 288 blocks (about 2 days) */
    bool can_prune = height < best->height - 288;
    dsv_block_index_free(best);
    
    return can_prune;
}

int dsv_storage_prune_blocks(dsv_storage_t *storage, int64_t height) {
    (void)storage;
    (void)height;
    /* TODO: Implement block file pruning */
    return DSV_OK;
}

