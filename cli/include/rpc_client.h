/**
 * DSV CLI RPC Client Header
 * 
 * JSON-RPC client for communicating with the DSV node.
 */

#ifndef DSV_RPC_CLIENT_H
#define DSV_RPC_CLIENT_H

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RPC client handle */
typedef struct dsv_rpc_client dsv_rpc_client_t;

/* RPC error */
typedef struct {
    int code;
    char *message;
} dsv_rpc_error_t;

/**
 * Create a new RPC client.
 * 
 * @param host   Node hostname (NULL for localhost)
 * @param port   Node RPC port (0 for default 8332)
 * @param user   RPC username (NULL for no auth)
 * @param pass   RPC password
 * @return       Client handle or NULL on error
 */
dsv_rpc_client_t *dsv_rpc_client_new(const char *host, int port,
                                      const char *user, const char *pass);

/**
 * Free RPC client.
 */
void dsv_rpc_client_free(dsv_rpc_client_t *client);

/**
 * Set request timeout.
 * 
 * @param client     Client handle
 * @param timeout_ms Timeout in milliseconds
 */
void dsv_rpc_client_set_timeout(dsv_rpc_client_t *client, int timeout_ms);

/**
 * Call an RPC method.
 * 
 * @param client Client handle
 * @param method Method name
 * @param params Parameters (cJSON array or object, NULL for no params)
 * @param error  Output error (can be NULL)
 * @return       JSON result string (caller must free) or NULL on error
 */
char *dsv_rpc_call(dsv_rpc_client_t *client, const char *method,
                   cJSON *params, dsv_rpc_error_t *error);

/* Convenience wrappers */

/**
 * Get current block count.
 * @return Block height or -1 on error
 */
int dsv_rpc_get_block_count(dsv_rpc_client_t *client);

/**
 * Get best block hash.
 * @return Hash string (caller must free) or NULL on error
 */
char *dsv_rpc_get_best_block_hash(dsv_rpc_client_t *client);

/**
 * Get block by hash.
 * @return Block JSON (caller must free) or NULL on error
 */
char *dsv_rpc_get_block(dsv_rpc_client_t *client, const char *hash);

/**
 * Get block hash by height.
 * @return Hash string (caller must free) or NULL on error
 */
char *dsv_rpc_get_block_hash(dsv_rpc_client_t *client, int height);

/**
 * Get raw transaction by txid.
 * @return Transaction JSON (caller must free) or NULL on error
 */
char *dsv_rpc_get_raw_transaction(dsv_rpc_client_t *client, const char *txid);

/**
 * Send raw transaction.
 * @return 1 on success, 0 on failure
 */
int dsv_rpc_send_raw_transaction(dsv_rpc_client_t *client, const char *hex_tx);

#ifdef __cplusplus
}
#endif

#endif /* DSV_RPC_CLIENT_H */

