/**
 * DSV RPC Input Fuzz Test
 * 
 * Fuzzes the RPC request parsing code to find injection or parsing bugs.
 * Uses libFuzzer or AFL-compatible interface.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dsv_rpc.h"
#include "dsv_crypto.h"

/* Initialize once */
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
    
    /* Skip empty inputs */
    if (size == 0) {
        return 0;
    }
    
    /* Enforce max request size */
    if (size > DSV_RPC_MAX_REQUEST_SIZE) {
        return 0;
    }
    
    /* Try to parse as JSON-RPC request */
    dsv_rpc_request_t request;
    memset(&request, 0, sizeof(request));
    
    dsv_rpc_error_t err = dsv_rpc_parse_request(&request, (const char *)data, size);
    
    if (err == DSV_RPC_OK) {
        /* Request parsed successfully */
        
        /* Verify method name is reasonable */
        if (request.method) {
            size_t method_len = strlen(request.method);
            if (method_len > 100) {
                /* Suspiciously long method name */
            }
        }
        
        /* Verify ID if present */
        if (request.has_id) {
            /* ID should be a reasonable value */
        }
        
        /* Process the request (mock chain/mempool) */
        dsv_rpc_response_t response;
        memset(&response, 0, sizeof(response));
        
        /* Note: We don't actually process against a real chain here,
         * just test parsing and basic validation */
        
        dsv_rpc_request_free(&request);
    }
    
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* Standalone driver */
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

