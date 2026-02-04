/**
 * DSV Serialization Implementation
 */

#include "dsv_serialize.h"
#include "dsv_crypto.h"
#include "dsv_u320.h"
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
 * Buffer Operations
 * ========================================================================== */

dsv_buffer_t *dsv_buffer_new(size_t initial_size) {
    dsv_buffer_t *buf = malloc(sizeof(dsv_buffer_t));
    if (!buf) return NULL;
    
    buf->data = malloc(initial_size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    buf->size = initial_size;
    buf->pos = 0;
    buf->owned = true;
    return buf;
}

dsv_buffer_t *dsv_buffer_from_data(const uint8_t *data, size_t size) {
    dsv_buffer_t *buf = malloc(sizeof(dsv_buffer_t));
    if (!buf) return NULL;
    
    buf->data = (uint8_t *)data;  /* Cast away const - we won't modify */
    buf->size = size;
    buf->pos = 0;
    buf->owned = false;
    return buf;
}

void dsv_buffer_free(dsv_buffer_t *buf) {
    if (!buf) return;
    if (buf->owned && buf->data) {
        free(buf->data);
    }
    free(buf);
}

void dsv_buffer_reset(dsv_buffer_t *buf) {
    buf->pos = 0;
}

size_t dsv_buffer_remaining(const dsv_buffer_t *buf) {
    return buf->size - buf->pos;
}

bool dsv_buffer_ensure(dsv_buffer_t *buf, size_t additional) {
    if (!buf->owned) return false;
    
    size_t needed = buf->pos + additional;
    if (needed <= buf->size) return true;
    
    size_t new_size = buf->size * 2;
    while (new_size < needed) new_size *= 2;
    
    uint8_t *new_data = realloc(buf->data, new_size);
    if (!new_data) return false;
    
    buf->data = new_data;
    buf->size = new_size;
    return true;
}

/* ==========================================================================
 * Primitive Write Operations
 * ========================================================================== */

bool dsv_write_u8(dsv_buffer_t *buf, uint8_t v) {
    if (!dsv_buffer_ensure(buf, 1)) return false;
    buf->data[buf->pos++] = v;
    return true;
}

bool dsv_write_u16(dsv_buffer_t *buf, uint16_t v) {
    if (!dsv_buffer_ensure(buf, 2)) return false;
    buf->data[buf->pos++] = (uint8_t)(v & 0xFF);
    buf->data[buf->pos++] = (uint8_t)((v >> 8) & 0xFF);
    return true;
}

bool dsv_write_u32(dsv_buffer_t *buf, uint32_t v) {
    if (!dsv_buffer_ensure(buf, 4)) return false;
    buf->data[buf->pos++] = (uint8_t)(v & 0xFF);
    buf->data[buf->pos++] = (uint8_t)((v >> 8) & 0xFF);
    buf->data[buf->pos++] = (uint8_t)((v >> 16) & 0xFF);
    buf->data[buf->pos++] = (uint8_t)((v >> 24) & 0xFF);
    return true;
}

bool dsv_write_u64(dsv_buffer_t *buf, uint64_t v) {
    if (!dsv_buffer_ensure(buf, 8)) return false;
    for (int i = 0; i < 8; i++) {
        buf->data[buf->pos++] = (uint8_t)((v >> (i * 8)) & 0xFF);
    }
    return true;
}

bool dsv_write_u320(dsv_buffer_t *buf, const dsv_u320_t *v) {
    if (!dsv_buffer_ensure(buf, 40)) return false;
    uint8_t bytes[40];
    dsv_u320_to_bytes(v, bytes);
    memcpy(buf->data + buf->pos, bytes, 40);
    buf->pos += 40;
    return true;
}

bool dsv_write_hash(dsv_buffer_t *buf, const dsv_hash256_t *h) {
    if (!dsv_buffer_ensure(buf, DSV_HASH_SIZE)) return false;
    memcpy(buf->data + buf->pos, h->data, DSV_HASH_SIZE);
    buf->pos += DSV_HASH_SIZE;
    return true;
}

bool dsv_write_bytes(dsv_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!dsv_buffer_ensure(buf, len)) return false;
    memcpy(buf->data + buf->pos, data, len);
    buf->pos += len;
    return true;
}

bool dsv_write_varint(dsv_buffer_t *buf, uint64_t v) {
    if (v < 0xFD) {
        return dsv_write_u8(buf, (uint8_t)v);
    } else if (v <= 0xFFFF) {
        if (!dsv_write_u8(buf, 0xFD)) return false;
        return dsv_write_u16(buf, (uint16_t)v);
    } else if (v <= 0xFFFFFFFF) {
        if (!dsv_write_u8(buf, 0xFE)) return false;
        return dsv_write_u32(buf, (uint32_t)v);
    } else {
        if (!dsv_write_u8(buf, 0xFF)) return false;
        return dsv_write_u64(buf, v);
    }
}

/* ==========================================================================
 * Primitive Read Operations
 * ========================================================================== */

bool dsv_read_u8(dsv_buffer_t *buf, uint8_t *v) {
    if (dsv_buffer_remaining(buf) < 1) return false;
    *v = buf->data[buf->pos++];
    return true;
}

bool dsv_read_u16(dsv_buffer_t *buf, uint16_t *v) {
    if (dsv_buffer_remaining(buf) < 2) return false;
    *v = buf->data[buf->pos] | ((uint16_t)buf->data[buf->pos + 1] << 8);
    buf->pos += 2;
    return true;
}

bool dsv_read_u32(dsv_buffer_t *buf, uint32_t *v) {
    if (dsv_buffer_remaining(buf) < 4) return false;
    *v = buf->data[buf->pos] | 
         ((uint32_t)buf->data[buf->pos + 1] << 8) |
         ((uint32_t)buf->data[buf->pos + 2] << 16) |
         ((uint32_t)buf->data[buf->pos + 3] << 24);
    buf->pos += 4;
    return true;
}

bool dsv_read_u64(dsv_buffer_t *buf, uint64_t *v) {
    if (dsv_buffer_remaining(buf) < 8) return false;
    *v = 0;
    for (int i = 0; i < 8; i++) {
        *v |= ((uint64_t)buf->data[buf->pos + i]) << (i * 8);
    }
    buf->pos += 8;
    return true;
}

bool dsv_read_u320(dsv_buffer_t *buf, dsv_u320_t *v) {
    if (dsv_buffer_remaining(buf) < 40) return false;
    dsv_u320_from_bytes(v, buf->data + buf->pos);
    buf->pos += 40;
    return true;
}

bool dsv_read_hash(dsv_buffer_t *buf, dsv_hash256_t *h) {
    if (dsv_buffer_remaining(buf) < DSV_HASH_SIZE) return false;
    memcpy(h->data, buf->data + buf->pos, DSV_HASH_SIZE);
    buf->pos += DSV_HASH_SIZE;
    return true;
}

bool dsv_read_bytes(dsv_buffer_t *buf, uint8_t *data, size_t len) {
    if (dsv_buffer_remaining(buf) < len) return false;
    memcpy(data, buf->data + buf->pos, len);
    buf->pos += len;
    return true;
}

bool dsv_read_varint(dsv_buffer_t *buf, uint64_t *v) {
    uint8_t first;
    if (!dsv_read_u8(buf, &first)) return false;
    
    if (first < 0xFD) {
        *v = first;
        return true;
    } else if (first == 0xFD) {
        uint16_t val;
        if (!dsv_read_u16(buf, &val)) return false;
        *v = val;
        return true;
    } else if (first == 0xFE) {
        uint32_t val;
        if (!dsv_read_u32(buf, &val)) return false;
        *v = val;
        return true;
    } else {
        return dsv_read_u64(buf, v);
    }
}

/* ==========================================================================
 * Transaction Memory Management
 * ========================================================================== */

dsv_tx_t *dsv_tx_new(void) {
    dsv_tx_t *tx = calloc(1, sizeof(dsv_tx_t));
    if (!tx) return NULL;
    tx->version = 1;
    return tx;
}

void dsv_tx_free(dsv_tx_t *tx) {
    if (!tx) return;
    
    if (tx->inputs) {
        dsv_secure_zero(tx->inputs, tx->input_count * sizeof(dsv_txin_t));
        free(tx->inputs);
    }
    if (tx->outputs) {
        free(tx->outputs);
    }
    
    dsv_secure_zero(tx, sizeof(dsv_tx_t));
    free(tx);
}

dsv_tx_t *dsv_tx_copy(const dsv_tx_t *tx) {
    if (!tx) return NULL;
    
    dsv_tx_t *copy = dsv_tx_new();
    if (!copy) return NULL;
    
    copy->version = tx->version;
    copy->locktime = tx->locktime;
    copy->input_count = tx->input_count;
    copy->output_count = tx->output_count;
    
    if (tx->input_count > 0) {
        copy->inputs = malloc(tx->input_count * sizeof(dsv_txin_t));
        if (!copy->inputs) {
            dsv_tx_free(copy);
            return NULL;
        }
        memcpy(copy->inputs, tx->inputs, tx->input_count * sizeof(dsv_txin_t));
    }
    
    if (tx->output_count > 0) {
        copy->outputs = malloc(tx->output_count * sizeof(dsv_txout_t));
        if (!copy->outputs) {
            dsv_tx_free(copy);
            return NULL;
        }
        memcpy(copy->outputs, tx->outputs, tx->output_count * sizeof(dsv_txout_t));
    }
    
    return copy;
}

/* ==========================================================================
 * Transaction Serialization
 * ========================================================================== */

size_t dsv_tx_serialized_size(const dsv_tx_t *tx) {
    size_t size = 4;  /* version */
    
    /* Input count (varint) + inputs */
    size += (tx->input_count < 0xFD) ? 1 : 
            (tx->input_count <= 0xFFFF) ? 3 : 5;
    size += tx->input_count * (32 + 4 + 32 + 64);  /* prevtxid + prevout + pubkey + sig */
    
    /* Output count (varint) + outputs */
    size += (tx->output_count < 0xFD) ? 1 :
            (tx->output_count <= 0xFFFF) ? 3 : 5;
    size += tx->output_count * (40 + 21);  /* amount + address */
    
    size += 4;  /* locktime */
    
    return size;
}

bool dsv_tx_serialize(dsv_buffer_t *buf, const dsv_tx_t *tx) {
    if (!dsv_write_u32(buf, tx->version)) return false;
    
    /* Inputs */
    if (!dsv_write_varint(buf, tx->input_count)) return false;
    for (uint32_t i = 0; i < tx->input_count; i++) {
        const dsv_txin_t *in = &tx->inputs[i];
        if (!dsv_write_hash(buf, &in->prev_txid)) return false;
        if (!dsv_write_u32(buf, in->prev_vout)) return false;
        if (!dsv_write_bytes(buf, in->pubkey.data, DSV_PUBKEY_SIZE)) return false;
        if (!dsv_write_bytes(buf, in->signature.data, DSV_SIGNATURE_SIZE)) return false;
    }
    
    /* Outputs */
    if (!dsv_write_varint(buf, tx->output_count)) return false;
    for (uint32_t i = 0; i < tx->output_count; i++) {
        const dsv_txout_t *out = &tx->outputs[i];
        if (!dsv_write_u320(buf, &out->amount)) return false;
        if (!dsv_write_u8(buf, out->address.version)) return false;
        if (!dsv_write_bytes(buf, out->address.hash, 20)) return false;
    }
    
    if (!dsv_write_u32(buf, tx->locktime)) return false;
    
    return true;
}

dsv_tx_t *dsv_tx_deserialize(dsv_buffer_t *buf) {
    dsv_tx_t *tx = dsv_tx_new();
    if (!tx) return NULL;
    
    if (!dsv_read_u32(buf, &tx->version)) goto fail;
    
    /* Inputs */
    uint64_t input_count;
    if (!dsv_read_varint(buf, &input_count)) goto fail;
    if (input_count > DSV_MAX_INPUTS) goto fail;
    
    tx->input_count = (uint32_t)input_count;
    if (tx->input_count > 0) {
        tx->inputs = calloc(tx->input_count, sizeof(dsv_txin_t));
        if (!tx->inputs) goto fail;
        
        for (uint32_t i = 0; i < tx->input_count; i++) {
            dsv_txin_t *in = &tx->inputs[i];
            if (!dsv_read_hash(buf, &in->prev_txid)) goto fail;
            if (!dsv_read_u32(buf, &in->prev_vout)) goto fail;
            if (!dsv_read_bytes(buf, in->pubkey.data, DSV_PUBKEY_SIZE)) goto fail;
            if (!dsv_read_bytes(buf, in->signature.data, DSV_SIGNATURE_SIZE)) goto fail;
        }
    }
    
    /* Outputs */
    uint64_t output_count;
    if (!dsv_read_varint(buf, &output_count)) goto fail;
    if (output_count > DSV_MAX_OUTPUTS) goto fail;
    
    tx->output_count = (uint32_t)output_count;
    if (tx->output_count > 0) {
        tx->outputs = calloc(tx->output_count, sizeof(dsv_txout_t));
        if (!tx->outputs) goto fail;
        
        for (uint32_t i = 0; i < tx->output_count; i++) {
            dsv_txout_t *out = &tx->outputs[i];
            if (!dsv_read_u320(buf, &out->amount)) goto fail;
            if (!dsv_read_u8(buf, &out->address.version)) goto fail;
            if (!dsv_read_bytes(buf, out->address.hash, 20)) goto fail;
        }
    }
    
    if (!dsv_read_u32(buf, &tx->locktime)) goto fail;
    
    return tx;
    
fail:
    dsv_tx_free(tx);
    return NULL;
}

void dsv_tx_compute_txid(dsv_hash256_t *txid, const dsv_tx_t *tx) {
    dsv_buffer_t *buf = dsv_buffer_new(dsv_tx_serialized_size(tx));
    if (!buf) {
        memset(txid, 0, sizeof(*txid));
        return;
    }
    
    dsv_tx_serialize(buf, tx);
    dsv_hash256(txid, buf->data, buf->pos);
    dsv_buffer_free(buf);
}

bool dsv_tx_serialize_for_signing(dsv_buffer_t *buf, const dsv_tx_t *tx,
                                   uint32_t input_index) {
    if (!dsv_write_u32(buf, tx->version)) return false;
    
    /* Inputs - with empty signature for all except the one being signed */
    if (!dsv_write_varint(buf, tx->input_count)) return false;
    for (uint32_t i = 0; i < tx->input_count; i++) {
        const dsv_txin_t *in = &tx->inputs[i];
        if (!dsv_write_hash(buf, &in->prev_txid)) return false;
        if (!dsv_write_u32(buf, in->prev_vout)) return false;
        if (!dsv_write_bytes(buf, in->pubkey.data, DSV_PUBKEY_SIZE)) return false;
        
        /* Empty signature except for current input */
        uint8_t empty_sig[DSV_SIGNATURE_SIZE] = {0};
        if (i == input_index) {
            /* Include the actual pubkey for signature */
            if (!dsv_write_bytes(buf, in->pubkey.data, DSV_PUBKEY_SIZE)) return false;
        } else {
            if (!dsv_write_bytes(buf, empty_sig, DSV_SIGNATURE_SIZE)) return false;
        }
    }
    
    /* Outputs */
    if (!dsv_write_varint(buf, tx->output_count)) return false;
    for (uint32_t i = 0; i < tx->output_count; i++) {
        const dsv_txout_t *out = &tx->outputs[i];
        if (!dsv_write_u320(buf, &out->amount)) return false;
        if (!dsv_write_u8(buf, out->address.version)) return false;
        if (!dsv_write_bytes(buf, out->address.hash, 20)) return false;
    }
    
    if (!dsv_write_u32(buf, tx->locktime)) return false;
    
    return true;
}

/* ==========================================================================
 * Block Memory Management
 * ========================================================================== */

dsv_block_t *dsv_block_new(void) {
    dsv_block_t *block = calloc(1, sizeof(dsv_block_t));
    if (!block) return NULL;
    block->header.version = 1;
    return block;
}

void dsv_block_free(dsv_block_t *block) {
    if (!block) return;
    
    if (block->txs) {
        for (uint32_t i = 0; i < block->tx_count; i++) {
            dsv_tx_free(block->txs[i]);
        }
        free(block->txs);
    }
    
    free(block);
}

bool dsv_block_add_tx(dsv_block_t *block, dsv_tx_t *tx) {
    dsv_tx_t **new_txs = realloc(block->txs, (block->tx_count + 1) * sizeof(dsv_tx_t *));
    if (!new_txs) return false;
    
    block->txs = new_txs;
    block->txs[block->tx_count++] = tx;
    return true;
}

/* ==========================================================================
 * Block Serialization
 * ========================================================================== */

bool dsv_block_header_serialize(dsv_buffer_t *buf, const dsv_block_header_t *hdr) {
    if (!dsv_write_u32(buf, hdr->version)) return false;
    if (!dsv_write_hash(buf, &hdr->prev_hash)) return false;
    if (!dsv_write_hash(buf, &hdr->merkle_root)) return false;
    if (!dsv_write_u32(buf, hdr->timestamp)) return false;
    if (!dsv_write_u32(buf, hdr->bits)) return false;
    if (!dsv_write_u32(buf, hdr->nonce)) return false;
    return true;
}

bool dsv_block_header_deserialize(dsv_buffer_t *buf, dsv_block_header_t *hdr) {
    if (!dsv_read_u32(buf, &hdr->version)) return false;
    if (!dsv_read_hash(buf, &hdr->prev_hash)) return false;
    if (!dsv_read_hash(buf, &hdr->merkle_root)) return false;
    if (!dsv_read_u32(buf, &hdr->timestamp)) return false;
    if (!dsv_read_u32(buf, &hdr->bits)) return false;
    if (!dsv_read_u32(buf, &hdr->nonce)) return false;
    return true;
}

bool dsv_block_serialize(dsv_buffer_t *buf, const dsv_block_t *block) {
    if (!dsv_block_header_serialize(buf, &block->header)) return false;
    if (!dsv_write_varint(buf, block->tx_count)) return false;
    
    for (uint32_t i = 0; i < block->tx_count; i++) {
        if (!dsv_tx_serialize(buf, block->txs[i])) return false;
    }
    
    return true;
}

dsv_block_t *dsv_block_deserialize(dsv_buffer_t *buf) {
    dsv_block_t *block = dsv_block_new();
    if (!block) return NULL;
    
    if (!dsv_block_header_deserialize(buf, &block->header)) goto fail;
    
    uint64_t tx_count;
    if (!dsv_read_varint(buf, &tx_count)) goto fail;
    if (tx_count > DSV_MAX_BLOCK_SIZE / 100) goto fail;  /* Reasonable limit */
    
    block->tx_count = 0;
    for (uint64_t i = 0; i < tx_count; i++) {
        dsv_tx_t *tx = dsv_tx_deserialize(buf);
        if (!tx) goto fail;
        if (!dsv_block_add_tx(block, tx)) {
            dsv_tx_free(tx);
            goto fail;
        }
    }
    
    return block;
    
fail:
    dsv_block_free(block);
    return NULL;
}

void dsv_block_compute_hash(dsv_hash256_t *hash, const dsv_block_header_t *hdr) {
    dsv_buffer_t *buf = dsv_buffer_new(DSV_BLOCK_HEADER_SIZE);
    if (!buf) {
        memset(hash, 0, sizeof(*hash));
        return;
    }
    
    dsv_block_header_serialize(buf, hdr);
    dsv_hash256(hash, buf->data, buf->pos);
    
    dsv_buffer_free(buf);
}

/* ==========================================================================
 * Address Serialization
 * ========================================================================== */

bool dsv_address_serialize(dsv_buffer_t *buf, const dsv_address_t *addr) {
    if (!dsv_write_u8(buf, addr->version)) return false;
    if (!dsv_write_bytes(buf, addr->hash, 20)) return false;
    return true;
}

bool dsv_address_deserialize(dsv_buffer_t *buf, dsv_address_t *addr) {
    if (!dsv_read_u8(buf, &addr->version)) return false;
    if (!dsv_read_bytes(buf, addr->hash, 20)) return false;
    return true;
}

