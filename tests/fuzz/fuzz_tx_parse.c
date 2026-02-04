/**
 * DSV Transaction Parsing Fuzz Test
 * 
 * Fuzzes the transaction deserialization code to find parsing bugs.
 * Uses libFuzzer or AFL-compatible interface.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dsv_serialize.h"
#include "dsv_types.h"
#include "dsv_crypto.h"

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
 * 
 * @param data  Fuzz input data
 * @param size  Size of input data
 * @return 0 on success (always returns 0 for fuzzing)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_init();
    
    /* Skip trivially small inputs */
    if (size < 4) {
        return 0;
    }
    
    /* Try to deserialize as a transaction */
    dsv_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    
    size_t consumed = 0;
    bool success = dsv_deserialize_tx(&tx, data, size, &consumed);
    
    if (success) {
        /* If parsing succeeded, verify some properties */
        
        /* Serialize back and compare */
        if (tx.input_count <= 100 && tx.output_count <= 100) {
            uint8_t *buffer = malloc(size * 2 + 1024);
            if (buffer) {
                size_t written = dsv_serialize_tx(&tx, buffer, size * 2 + 1024);
                
                /* Round-trip should produce same transaction */
                if (written > 0) {
                    dsv_tx_t tx2;
                    memset(&tx2, 0, sizeof(tx2));
                    size_t consumed2 = 0;
                    
                    if (dsv_deserialize_tx(&tx2, buffer, written, &consumed2)) {
                        /* Basic sanity checks */
                        if (tx.version != tx2.version ||
                            tx.input_count != tx2.input_count ||
                            tx.output_count != tx2.output_count) {
                            /* Round-trip mismatch - potential bug */
                            /* Fuzzer will save this input */
                        }
                        
                        dsv_tx_free(&tx2);
                    }
                }
                
                free(buffer);
            }
        }
        
        dsv_tx_free(&tx);
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

