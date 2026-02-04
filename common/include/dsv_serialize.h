/**
 * DSV Serialization
 * 
 * Binary serialization for transactions and blocks.
 * All multi-byte integers are little-endian.
 */

#ifndef DSV_SERIALIZE_H
#define DSV_SERIALIZE_H

#include "dsv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Buffer Operations
 * ========================================================================== */

typedef struct {
    uint8_t *data;
    size_t size;
    size_t pos;
    bool owned;  /* True if we allocated the buffer */
} dsv_buffer_t;

/* Initialize buffer for writing */
dsv_buffer_t *dsv_buffer_new(size_t initial_size);

/* Initialize buffer for reading */
dsv_buffer_t *dsv_buffer_from_data(const uint8_t *data, size_t size);

/* Free buffer */
void dsv_buffer_free(dsv_buffer_t *buf);

/* Reset position to beginning */
void dsv_buffer_reset(dsv_buffer_t *buf);

/* Get remaining bytes */
size_t dsv_buffer_remaining(const dsv_buffer_t *buf);

/* Ensure capacity for writing */
bool dsv_buffer_ensure(dsv_buffer_t *buf, size_t additional);

/* ==========================================================================
 * Primitive Write Operations
 * ========================================================================== */

bool dsv_write_u8(dsv_buffer_t *buf, uint8_t v);
bool dsv_write_u16(dsv_buffer_t *buf, uint16_t v);
bool dsv_write_u32(dsv_buffer_t *buf, uint32_t v);
bool dsv_write_u64(dsv_buffer_t *buf, uint64_t v);
bool dsv_write_u320(dsv_buffer_t *buf, const dsv_u320_t *v);
bool dsv_write_hash(dsv_buffer_t *buf, const dsv_hash256_t *h);
bool dsv_write_bytes(dsv_buffer_t *buf, const uint8_t *data, size_t len);

/* Variable-length integer (Bitcoin-style compact size) */
bool dsv_write_varint(dsv_buffer_t *buf, uint64_t v);

/* ==========================================================================
 * Primitive Read Operations
 * ========================================================================== */

bool dsv_read_u8(dsv_buffer_t *buf, uint8_t *v);
bool dsv_read_u16(dsv_buffer_t *buf, uint16_t *v);
bool dsv_read_u32(dsv_buffer_t *buf, uint32_t *v);
bool dsv_read_u64(dsv_buffer_t *buf, uint64_t *v);
bool dsv_read_u320(dsv_buffer_t *buf, dsv_u320_t *v);
bool dsv_read_hash(dsv_buffer_t *buf, dsv_hash256_t *h);
bool dsv_read_bytes(dsv_buffer_t *buf, uint8_t *data, size_t len);
bool dsv_read_varint(dsv_buffer_t *buf, uint64_t *v);

/* ==========================================================================
 * Transaction Serialization
 * ========================================================================== */

/* Serialize transaction to buffer */
bool dsv_tx_serialize(dsv_buffer_t *buf, const dsv_tx_t *tx);

/* Deserialize transaction from buffer */
dsv_tx_t *dsv_tx_deserialize(dsv_buffer_t *buf);

/* Get serialized size of transaction */
size_t dsv_tx_serialized_size(const dsv_tx_t *tx);

/* Compute transaction ID (double SHA-256 of serialized tx) */
void dsv_tx_compute_txid(dsv_hash256_t *txid, const dsv_tx_t *tx);

/* Serialize transaction for signing (without signatures) */
bool dsv_tx_serialize_for_signing(dsv_buffer_t *buf, const dsv_tx_t *tx, 
                                   uint32_t input_index);

/* ==========================================================================
 * Block Serialization
 * ========================================================================== */

/* Serialize block header */
bool dsv_block_header_serialize(dsv_buffer_t *buf, const dsv_block_header_t *hdr);

/* Deserialize block header */
bool dsv_block_header_deserialize(dsv_buffer_t *buf, dsv_block_header_t *hdr);

/* Serialize full block */
bool dsv_block_serialize(dsv_buffer_t *buf, const dsv_block_t *block);

/* Deserialize full block */
dsv_block_t *dsv_block_deserialize(dsv_buffer_t *buf);

/* Compute block hash (double SHA-256 of header) */
void dsv_block_compute_hash(dsv_hash256_t *hash, const dsv_block_header_t *hdr);

/* ==========================================================================
 * Address Serialization
 * ========================================================================== */

bool dsv_address_serialize(dsv_buffer_t *buf, const dsv_address_t *addr);
bool dsv_address_deserialize(dsv_buffer_t *buf, dsv_address_t *addr);

/* ==========================================================================
 * Memory Management
 * ========================================================================== */

/* Create empty transaction */
dsv_tx_t *dsv_tx_new(void);

/* Free transaction */
void dsv_tx_free(dsv_tx_t *tx);

/* Deep copy transaction */
dsv_tx_t *dsv_tx_copy(const dsv_tx_t *tx);

/* Create empty block */
dsv_block_t *dsv_block_new(void);

/* Free block */
void dsv_block_free(dsv_block_t *block);

/* Add transaction to block */
bool dsv_block_add_tx(dsv_block_t *block, dsv_tx_t *tx);

#ifdef __cplusplus
}
#endif

#endif /* DSV_SERIALIZE_H */

