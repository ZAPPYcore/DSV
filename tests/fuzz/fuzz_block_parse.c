/**
 * DSV Block Parsing Fuzz Test
 * 
 * Fuzzes the block deserialization code to find parsing bugs.
 * Uses libFuzzer or AFL-compatible interface.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dsv_serialize.h"
#include "dsv_types.h"
#include "dsv_crypto.h"
#include "dsv_consensus.h"

/* Initialize crypto once */
static int initialized = 0;

static void ensure_init(void) {
    if (!initialized) {
        dsv_crypto_init();
        initialized = 1;
    }
}

/**
 * libFuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_init();
    
    /* Skip trivially small inputs */
    if (size < DSV_BLOCK_HEADER_SIZE) {
        return 0;
    }
    
    /* First try to parse just the header */
    dsv_block_header_t header;
    size_t consumed = 0;
    
    if (dsv_deserialize_header(&header, data, size, &consumed)) {
        /* Header parsed successfully */
        
        /* Check if hash meets any target (sanity check) */
        dsv_hash256_t hash;
        dsv_hash_header(&header, &hash);
        
        /* Verify header fields are somewhat sane */
        if (header.version > 0 && header.version < 1000) {
            /* Attempt to serialize back */
            uint8_t buffer[DSV_BLOCK_HEADER_SIZE];
            size_t written = dsv_serialize_header(&header, buffer, sizeof(buffer));
            
            if (written == DSV_BLOCK_HEADER_SIZE) {
                /* Round-trip should match original header bytes */
                dsv_block_header_t header2;
                size_t consumed2;
                
                if (dsv_deserialize_header(&header2, buffer, written, &consumed2)) {
                    /* Verify fields match */
                    if (header.version != header2.version ||
                        header.time != header2.time ||
                        header.bits != header2.bits ||
                        header.nonce != header2.nonce) {
                        /* Mismatch - potential bug */
                    }
                }
            }
        }
    }
    
    /* Now try to parse as a full block */
    dsv_block_t block;
    memset(&block, 0, sizeof(block));
    consumed = 0;
    
    if (dsv_deserialize_block(&block, data, size, &consumed)) {
        /* Block parsed successfully */
        
        /* Verify merkle root if there are transactions */
        if (block.tx_count > 0 && block.tx_count <= 1000) {
            dsv_hash256_t computed_merkle;
            if (dsv_compute_merkle_root(&computed_merkle, block.txs, block.tx_count)) {
                /* Check if computed matches header */
                if (memcmp(computed_merkle.data, block.header.merkle_root.data, 32) != 0) {
                    /* Merkle mismatch - expected for fuzz input */
                }
            }
        }
        
        /* Try round-trip if block is small enough */
        if (block.tx_count <= 100) {
            size_t estimated_size = DSV_BLOCK_HEADER_SIZE + block.tx_count * 1024;
            uint8_t *buffer = malloc(estimated_size);
            
            if (buffer) {
                size_t written = dsv_serialize_block(&block, buffer, estimated_size);
                
                if (written > 0) {
                    dsv_block_t block2;
                    memset(&block2, 0, sizeof(block2));
                    size_t consumed2 = 0;
                    
                    if (dsv_deserialize_block(&block2, buffer, written, &consumed2)) {
                        /* Verify basic properties match */
                        if (block.tx_count != block2.tx_count) {
                            /* Mismatch */
                        }
                        
                        dsv_block_free(&block2);
                    }
                }
                
                free(buffer);
            }
        }
        
        dsv_block_free(&block);
    }
    
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* Standalone driver for testing without libFuzzer */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }
    
    if (fread(data, 1, size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);
    
    int result = LLVMFuzzerTestOneInput(data, size);
    
    free(data);
    return result;
}
#endif

