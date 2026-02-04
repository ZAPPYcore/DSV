/**
 * DSV JSON-RPC Server
 * 
 * Security features:
 * - Localhost only by default
 * - Auth token required
 * - Request size limits
 * - Rate limiting
 * - Timeout protection
 */

#ifndef DSV_RPC_H
#define DSV_RPC_H

#include "dsv_types.h"
#include "dsv_chain.h"
#include "dsv_mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsv_rpc_server_s dsv_rpc_server_t;

/* ==========================================================================
 * RPC Configuration
 * ========================================================================== */

typedef struct {
    char *bind_address;      /* Default: 127.0.0.1 */
    uint16_t port;           /* Default: 8332 */
    char *auth_token;        /* Required for all requests */
    size_t max_request_size; /* Default: 1MB */
    int rate_limit_per_sec;  /* Default: 100 */
    int timeout_sec;         /* Default: 30 */
    bool allow_remote;       /* Default: false */
} dsv_rpc_config_t;

/**
 * Get default RPC config.
 */
dsv_rpc_config_t dsv_rpc_default_config(void);

/**
 * Free config resources.
 */
void dsv_rpc_config_free(dsv_rpc_config_t *config);

/* ==========================================================================
 * RPC Server
 * ========================================================================== */

/**
 * Create RPC server.
 */
dsv_rpc_server_t *dsv_rpc_server_new(const dsv_rpc_config_t *config,
                                      dsv_chain_t *chain,
                                      dsv_mempool_t *mempool);

/**
 * Start RPC server.
 */
int dsv_rpc_server_start(dsv_rpc_server_t *server);

/**
 * Stop RPC server.
 */
void dsv_rpc_server_stop(dsv_rpc_server_t *server);

/**
 * Destroy RPC server.
 */
void dsv_rpc_server_free(dsv_rpc_server_t *server);

/**
 * Check if server is running.
 */
bool dsv_rpc_server_running(dsv_rpc_server_t *server);

/* ==========================================================================
 * RPC Methods
 * ========================================================================== */

/* Chain queries */
#define RPC_GETBLOCKCHAININFO   "getblockchaininfo"
#define RPC_GETBLOCK            "getblock"
#define RPC_GETBLOCKHEADER      "getblockheader"
#define RPC_GETBLOCKHASH        "getblockhash"
#define RPC_GETBLOCKCOUNT       "getblockcount"
#define RPC_GETDIFFICULTY       "getdifficulty"
#define RPC_GETCHAINTIPS        "getchaintips"

/* Transaction queries */
#define RPC_GETRAWTRANSACTION   "getrawtransaction"
#define RPC_GETTXOUT            "gettxout"
#define RPC_SENDRAWTRANSACTION  "sendrawtransaction"
#define RPC_DECODERAWTRANSACTION "decoderawtransaction"

/* Mempool queries */
#define RPC_GETMEMPOOLINFO      "getmempoolinfo"
#define RPC_GETRAWMEMPOOL       "getrawmempool"

/* Mining */
#define RPC_GETBLOCKTEMPLATE    "getblocktemplate"
#define RPC_SUBMITBLOCK         "submitblock"
#define RPC_GETMININGINFO       "getmininginfo"

/* Address queries */
#define RPC_GETADDRESSINFO      "getaddressinfo"
#define RPC_GETADDRESSUTXOS     "getaddressutxos"
#define RPC_GETADDRESSBALANCE   "getaddressbalance"

/* Utility */
#define RPC_VALIDATEADDRESS     "validateaddress"
#define RPC_STOP                "stop"

#ifdef __cplusplus
}
#endif

#endif /* DSV_RPC_H */

