/**
 * DSV P2P Network Layer
 * 
 * Handles peer discovery, connection management, and message relay.
 */

#ifndef DSV_P2P_H
#define DSV_P2P_H

#include "dsv_types.h"
#include "dsv_chain.h"
#include "dsv_mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsv_p2p_s dsv_p2p_t;

/* ==========================================================================
 * P2P Configuration
 * ========================================================================== */

typedef struct {
    char *bind_address;
    uint16_t port;
    int max_peers;
    int max_outbound;
    char **seed_nodes;
    size_t seed_node_count;
    bool enable_listen;
} dsv_p2p_config_t;

/**
 * Get default P2P config.
 */
dsv_p2p_config_t dsv_p2p_default_config(void);

/**
 * Free P2P config.
 */
void dsv_p2p_config_free(dsv_p2p_config_t *config);

/* ==========================================================================
 * P2P Network Messages
 * ========================================================================== */

#define MSG_VERSION     "version"
#define MSG_VERACK      "verack"
#define MSG_PING        "ping"
#define MSG_PONG        "pong"
#define MSG_GETADDR     "getaddr"
#define MSG_ADDR        "addr"
#define MSG_INV         "inv"
#define MSG_GETDATA     "getdata"
#define MSG_GETBLOCKS   "getblocks"
#define MSG_GETHEADERS  "getheaders"
#define MSG_HEADERS     "headers"
#define MSG_BLOCK       "block"
#define MSG_TX          "tx"
#define MSG_NOTFOUND    "notfound"
#define MSG_REJECT      "reject"

/* Inventory types */
#define INV_TX          1
#define INV_BLOCK       2

/* ==========================================================================
 * P2P Network
 * ========================================================================== */

/**
 * Create P2P network.
 */
dsv_p2p_t *dsv_p2p_new(const dsv_p2p_config_t *config,
                        dsv_chain_t *chain,
                        dsv_mempool_t *mempool);

/**
 * Start P2P network.
 */
int dsv_p2p_start(dsv_p2p_t *p2p);

/**
 * Stop P2P network.
 */
void dsv_p2p_stop(dsv_p2p_t *p2p);

/**
 * Destroy P2P network.
 */
void dsv_p2p_free(dsv_p2p_t *p2p);

/**
 * Get number of connected peers.
 */
int dsv_p2p_peer_count(dsv_p2p_t *p2p);

/**
 * Broadcast transaction to peers.
 */
void dsv_p2p_broadcast_tx(dsv_p2p_t *p2p, const dsv_hash256_t *txid);

/**
 * Broadcast block to peers.
 */
void dsv_p2p_broadcast_block(dsv_p2p_t *p2p, const dsv_hash256_t *hash);

/**
 * Request block from peers.
 */
void dsv_p2p_request_block(dsv_p2p_t *p2p, const dsv_hash256_t *hash);

/**
 * Check if network is synced.
 */
bool dsv_p2p_is_synced(dsv_p2p_t *p2p);

#ifdef __cplusplus
}
#endif

#endif /* DSV_P2P_H */

