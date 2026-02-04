/**
 * DSV JSON-RPC Server Implementation
 * 
 * Uses libevent for HTTP handling.
 */

#include "dsv_rpc.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"
#include "dsv_consensus.h"
#include "dsv_u320.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <cjson/cJSON.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* Rate limiting state */
typedef struct {
    char ip[64];
    time_t window_start;
    int request_count;
} rate_limit_entry_t;

#define RATE_LIMIT_TABLE_SIZE 1024

struct dsv_rpc_server_s {
    dsv_rpc_config_t config;
    dsv_chain_t *chain;
    dsv_mempool_t *mempool;
    
    struct event_base *base;
    struct evhttp *http;
    pthread_t thread;
    bool running;
    bool should_stop;
    
    /* Rate limiting */
    rate_limit_entry_t rate_limits[RATE_LIMIT_TABLE_SIZE];
    pthread_mutex_t rate_lock;
};

/* Forward declarations */
static void handle_request(struct evhttp_request *req, void *arg);
static cJSON *dispatch_method(dsv_rpc_server_t *server, const char *method,
                              cJSON *params, int *error_code, char **error_msg);

/* ==========================================================================
 * Configuration
 * ========================================================================== */

dsv_rpc_config_t dsv_rpc_default_config(void) {
    dsv_rpc_config_t config;
    memset(&config, 0, sizeof(config));
    config.bind_address = strdup("127.0.0.1");
    config.port = 8332;
    config.auth_token = NULL;  /* Must be set by user */
    config.max_request_size = 1024 * 1024;  /* 1 MB */
    config.rate_limit_per_sec = 100;
    config.timeout_sec = 30;
    config.allow_remote = false;
    return config;
}

void dsv_rpc_config_free(dsv_rpc_config_t *config) {
    if (!config) return;
    free(config->bind_address);
    free(config->auth_token);
}

/* ==========================================================================
 * Rate Limiting
 * ========================================================================== */

static uint32_t hash_ip(const char *ip) {
    uint32_t hash = 5381;
    while (*ip) {
        hash = ((hash << 5) + hash) + (uint8_t)*ip++;
    }
    return hash % RATE_LIMIT_TABLE_SIZE;
}

static bool check_rate_limit(dsv_rpc_server_t *server, const char *ip) {
    pthread_mutex_lock(&server->rate_lock);
    
    uint32_t idx = hash_ip(ip);
    rate_limit_entry_t *entry = &server->rate_limits[idx];
    time_t now = time(NULL);
    
    /* Check if same IP and within window */
    if (strcmp(entry->ip, ip) == 0 && now - entry->window_start < 1) {
        if (entry->request_count >= server->config.rate_limit_per_sec) {
            pthread_mutex_unlock(&server->rate_lock);
            return false;
        }
        entry->request_count++;
    } else {
        /* New window or new IP */
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->ip[sizeof(entry->ip) - 1] = '\0';
        entry->window_start = now;
        entry->request_count = 1;
    }
    
    pthread_mutex_unlock(&server->rate_lock);
    return true;
}

/* ==========================================================================
 * Request Handling
 * ========================================================================== */

static void send_json_response(struct evhttp_request *req, int code, cJSON *json) {
    struct evbuffer *buf = evbuffer_new();
    char *json_str = cJSON_PrintUnformatted(json);
    
    evbuffer_add(buf, json_str, strlen(json_str));
    
    evhttp_add_header(evhttp_request_get_output_headers(req),
                      "Content-Type", "application/json");
    evhttp_send_reply(req, code, code == 200 ? "OK" : "Error", buf);
    
    free(json_str);
    evbuffer_free(buf);
}

static void send_error(struct evhttp_request *req, int http_code,
                       int rpc_code, const char *message, cJSON *id) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "jsonrpc", "2.0");
    cJSON_AddItemToObject(response, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    
    cJSON *error = cJSON_CreateObject();
    cJSON_AddNumberToObject(error, "code", rpc_code);
    cJSON_AddStringToObject(error, "message", message);
    cJSON_AddItemToObject(response, "error", error);
    
    send_json_response(req, http_code, response);
    cJSON_Delete(response);
}

static void handle_request(struct evhttp_request *req, void *arg) {
    dsv_rpc_server_t *server = arg;
    
    /* Only accept POST */
    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        evhttp_send_error(req, 405, "Method Not Allowed");
        return;
    }
    
    /* Get client IP */
    const char *client_ip = NULL;
    struct evhttp_connection *conn = evhttp_request_get_connection(req);
    if (conn) {
        char *addr;
        ev_uint16_t port;
        evhttp_connection_get_peer(conn, &addr, &port);
        client_ip = addr;
    }
    
    /* Check if remote connections allowed */
    if (!server->config.allow_remote && client_ip) {
        if (strcmp(client_ip, "127.0.0.1") != 0 &&
            strcmp(client_ip, "::1") != 0 &&
            strcmp(client_ip, "localhost") != 0) {
            evhttp_send_error(req, 403, "Remote connections not allowed");
            return;
        }
    }
    
    /* Rate limiting */
    if (client_ip && !check_rate_limit(server, client_ip)) {
        evhttp_send_error(req, 429, "Too Many Requests");
        return;
    }
    
    /* Check auth token */
    if (server->config.auth_token) {
        const char *auth = evhttp_find_header(evhttp_request_get_input_headers(req),
                                               "Authorization");
        if (!auth) {
            evhttp_send_error(req, 401, "Authorization required");
            return;
        }
        
        /* Expect "Bearer <token>" */
        if (strncmp(auth, "Bearer ", 7) != 0) {
            evhttp_send_error(req, 401, "Invalid authorization format");
            return;
        }
        
        if (!dsv_secure_compare(auth + 7, server->config.auth_token,
                                strlen(server->config.auth_token))) {
            evhttp_send_error(req, 401, "Invalid auth token");
            return;
        }
    }
    
    /* Get request body */
    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input);
    
    if (len == 0) {
        send_error(req, 400, -32700, "Empty request", NULL);
        return;
    }
    
    if (len > server->config.max_request_size) {
        send_error(req, 400, -32600, "Request too large", NULL);
        return;
    }
    
    char *body = malloc(len + 1);
    if (!body) {
        send_error(req, 500, -32603, "Internal error", NULL);
        return;
    }
    
    evbuffer_copyout(input, body, len);
    body[len] = '\0';
    
    /* Parse JSON */
    cJSON *request = cJSON_Parse(body);
    free(body);
    
    if (!request) {
        send_error(req, 400, -32700, "Parse error", NULL);
        return;
    }
    
    /* Extract method and params */
    cJSON *method_json = cJSON_GetObjectItem(request, "method");
    cJSON *params = cJSON_GetObjectItem(request, "params");
    cJSON *id = cJSON_GetObjectItem(request, "id");
    
    if (!method_json || !cJSON_IsString(method_json)) {
        send_error(req, 400, -32600, "Invalid request: missing method", id);
        cJSON_Delete(request);
        return;
    }
    
    const char *method = method_json->valuestring;
    
    /* Dispatch method */
    int error_code = 0;
    char *error_msg = NULL;
    cJSON *result = dispatch_method(server, method, params, &error_code, &error_msg);
    
    /* Build response */
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "jsonrpc", "2.0");
    cJSON_AddItemToObject(response, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    
    if (error_code != 0) {
        cJSON *error = cJSON_CreateObject();
        cJSON_AddNumberToObject(error, "code", error_code);
        cJSON_AddStringToObject(error, "message", error_msg ? error_msg : "Unknown error");
        cJSON_AddItemToObject(response, "error", error);
        free(error_msg);
    } else {
        cJSON_AddItemToObject(response, "result", result ? result : cJSON_CreateNull());
    }
    
    send_json_response(req, error_code ? 400 : 200, response);
    
    cJSON_Delete(response);
    cJSON_Delete(request);
}

/* ==========================================================================
 * RPC Method Implementations
 * ========================================================================== */

static cJSON *rpc_getblockchaininfo(dsv_rpc_server_t *server) {
    cJSON *result = cJSON_CreateObject();
    
    dsv_hash256_t best_hash;
    dsv_chain_get_best_hash(server->chain, &best_hash);
    
    char hash_hex[65];
    dsv_hash_to_hex(hash_hex, &best_hash);
    
    cJSON_AddStringToObject(result, "chain", "dsv");
    cJSON_AddNumberToObject(result, "blocks", (double)dsv_chain_get_height(server->chain));
    cJSON_AddStringToObject(result, "bestblockhash", hash_hex);
    cJSON_AddNumberToObject(result, "difficulty", 1.0);  /* TODO: Calculate actual difficulty */
    
    dsv_chainwork_t chainwork;
    dsv_chain_get_chainwork(server->chain, &chainwork);
    char chainwork_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(chainwork_hex + i * 2, "%02x", chainwork.data[i]);
    }
    cJSON_AddStringToObject(result, "chainwork", chainwork_hex);
    
    return result;
}

static cJSON *rpc_getblock(dsv_rpc_server_t *server, cJSON *params,
                           int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [blockhash]");
        return NULL;
    }
    
    cJSON *hash_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(hash_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: blockhash must be string");
        return NULL;
    }
    
    dsv_hash256_t hash;
    if (!dsv_hash_from_hex(&hash, hash_param->valuestring)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid block hash");
        return NULL;
    }
    
    dsv_block_t *block = dsv_chain_get_block(server->chain, &hash);
    if (!block) {
        *error_code = -5;
        *error_msg = strdup("Block not found");
        return NULL;
    }
    
    dsv_block_index_t *idx = dsv_chain_get_block_index(server->chain, &hash);
    
    cJSON *result = cJSON_CreateObject();
    
    char hash_hex[65];
    dsv_hash_to_hex(hash_hex, &hash);
    cJSON_AddStringToObject(result, "hash", hash_hex);
    
    cJSON_AddNumberToObject(result, "confirmations", 
                            dsv_chain_get_height(server->chain) - (idx ? idx->height : 0) + 1);
    cJSON_AddNumberToObject(result, "height", idx ? (double)idx->height : 0);
    cJSON_AddNumberToObject(result, "version", block->header.version);
    
    char merkle_hex[65];
    dsv_hash_to_hex(merkle_hex, &block->header.merkle_root);
    cJSON_AddStringToObject(result, "merkleroot", merkle_hex);
    
    cJSON *txs = cJSON_CreateArray();
    for (uint32_t i = 0; i < block->tx_count; i++) {
        dsv_hash256_t txid;
        dsv_tx_compute_txid(&txid, block->txs[i]);
        char txid_hex[65];
        dsv_hash_to_hex(txid_hex, &txid);
        cJSON_AddItemToArray(txs, cJSON_CreateString(txid_hex));
    }
    cJSON_AddItemToObject(result, "tx", txs);
    
    cJSON_AddNumberToObject(result, "time", block->header.timestamp);
    cJSON_AddNumberToObject(result, "nonce", block->header.nonce);
    cJSON_AddNumberToObject(result, "bits", block->header.bits);
    cJSON_AddNumberToObject(result, "nTx", block->tx_count);
    
    char prev_hex[65];
    dsv_hash_to_hex(prev_hex, &block->header.prev_hash);
    cJSON_AddStringToObject(result, "previousblockhash", prev_hex);
    
    if (idx) dsv_block_index_free(idx);
    dsv_block_free(block);
    
    return result;
}

static cJSON *rpc_getblockhash(dsv_rpc_server_t *server, cJSON *params,
                               int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [height]");
        return NULL;
    }
    
    cJSON *height_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsNumber(height_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: height must be number");
        return NULL;
    }
    
    int64_t height = (int64_t)height_param->valuedouble;
    
    dsv_block_index_t *idx = dsv_chain_get_block_at_height(server->chain, height);
    if (!idx) {
        *error_code = -8;
        *error_msg = strdup("Block height out of range");
        return NULL;
    }
    
    char hash_hex[65];
    dsv_hash_to_hex(hash_hex, &idx->hash);
    dsv_block_index_free(idx);
    
    return cJSON_CreateString(hash_hex);
}

static cJSON *rpc_getblockcount(dsv_rpc_server_t *server) {
    return cJSON_CreateNumber((double)dsv_chain_get_height(server->chain));
}

static cJSON *rpc_getrawtransaction(dsv_rpc_server_t *server, cJSON *params,
                                     int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [txid]");
        return NULL;
    }
    
    cJSON *txid_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(txid_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: txid must be string");
        return NULL;
    }
    
    dsv_hash256_t txid;
    if (!dsv_hash_from_hex(&txid, txid_param->valuestring)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid txid");
        return NULL;
    }
    
    /* Check mempool first */
    if (server->mempool) {
        dsv_tx_t *tx = dsv_mempool_get(server->mempool, &txid);
        if (tx) {
            dsv_buffer_t *buf = dsv_buffer_new(dsv_tx_serialized_size(tx));
            dsv_tx_serialize(buf, tx);
            
            char *hex = malloc(buf->pos * 2 + 1);
            for (size_t i = 0; i < buf->pos; i++) {
                sprintf(hex + i * 2, "%02x", buf->data[i]);
            }
            
            cJSON *result = cJSON_CreateString(hex);
            free(hex);
            dsv_buffer_free(buf);
            dsv_tx_free(tx);
            return result;
        }
    }
    
    /* TODO: Search blockchain for tx */
    *error_code = -5;
    *error_msg = strdup("Transaction not found");
    return NULL;
}

static cJSON *rpc_sendrawtransaction(dsv_rpc_server_t *server, cJSON *params,
                                      int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [hexstring]");
        return NULL;
    }
    
    cJSON *hex_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(hex_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: hexstring must be string");
        return NULL;
    }
    
    const char *hex = hex_param->valuestring;
    size_t hex_len = strlen(hex);
    
    if (hex_len % 2 != 0 || hex_len > DSV_MAX_TX_SIZE * 2) {
        *error_code = -22;
        *error_msg = strdup("Invalid transaction hex");
        return NULL;
    }
    
    /* Decode hex */
    size_t bin_len = hex_len / 2;
    uint8_t *bin = malloc(bin_len);
    if (!bin) {
        *error_code = -32603;
        *error_msg = strdup("Out of memory");
        return NULL;
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            free(bin);
            *error_code = -22;
            *error_msg = strdup("Invalid hex encoding");
            return NULL;
        }
        bin[i] = (uint8_t)byte;
    }
    
    /* Deserialize transaction */
    dsv_buffer_t *buf = dsv_buffer_from_data(bin, bin_len);
    dsv_tx_t *tx = dsv_tx_deserialize(buf);
    dsv_buffer_free(buf);
    free(bin);
    
    if (!tx) {
        *error_code = -22;
        *error_msg = strdup("TX decode failed");
        return NULL;
    }
    
    /* Validate transaction */
    dsv_u320_t fee;
    int err = dsv_chain_validate_tx(server->chain, tx, &fee);
    if (err != DSV_OK) {
        dsv_tx_free(tx);
        *error_code = -26;
        *error_msg = strdup("Transaction validation failed");
        return NULL;
    }
    
    /* Add to mempool */
    if (server->mempool) {
        err = dsv_mempool_add(server->mempool, tx, &fee);
        if (err != DSV_OK) {
            dsv_tx_free(tx);
            *error_code = -26;
            *error_msg = strdup("Failed to add to mempool");
            return NULL;
        }
    }
    
    /* Return txid */
    dsv_hash256_t txid;
    dsv_tx_compute_txid(&txid, tx);
    dsv_tx_free(tx);
    
    char txid_hex[65];
    dsv_hash_to_hex(txid_hex, &txid);
    
    return cJSON_CreateString(txid_hex);
}

static cJSON *rpc_getmempoolinfo(dsv_rpc_server_t *server) {
    cJSON *result = cJSON_CreateObject();
    
    if (server->mempool) {
        cJSON_AddNumberToObject(result, "size", (double)dsv_mempool_size(server->mempool));
        cJSON_AddNumberToObject(result, "bytes", (double)dsv_mempool_memory_usage(server->mempool));
    } else {
        cJSON_AddNumberToObject(result, "size", 0);
        cJSON_AddNumberToObject(result, "bytes", 0);
    }
    
    return result;
}

static cJSON *rpc_getaddressbalance(dsv_rpc_server_t *server, cJSON *params,
                                     int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [address]");
        return NULL;
    }
    
    cJSON *addr_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(addr_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: address must be string");
        return NULL;
    }
    
    dsv_address_t addr;
    if (!dsv_address_decode(&addr, addr_param->valuestring)) {
        *error_code = -5;
        *error_msg = strdup("Invalid address");
        return NULL;
    }
    
    dsv_u320_t balance;
    dsv_chain_get_balance(server->chain, &addr, &balance);
    
    cJSON *result = cJSON_CreateObject();
    
    char balance_str[100];
    dsv_u320_to_dec(&balance, balance_str, sizeof(balance_str));
    cJSON_AddStringToObject(result, "balance", balance_str);
    
    char formatted[100];
    dsv_u320_format_dsv(&balance, formatted, sizeof(formatted));
    cJSON_AddStringToObject(result, "balance_dsv", formatted);
    
    return result;
}

static cJSON *rpc_getaddressutxos(dsv_rpc_server_t *server, cJSON *params,
                                   int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [address]");
        return NULL;
    }
    
    cJSON *addr_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(addr_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: address must be string");
        return NULL;
    }
    
    dsv_address_t addr;
    if (!dsv_address_decode(&addr, addr_param->valuestring)) {
        *error_code = -5;
        *error_msg = strdup("Invalid address");
        return NULL;
    }
    
    size_t count;
    dsv_utxo_t **utxos = dsv_chain_get_address_utxos(server->chain, &addr, &count);
    
    cJSON *result = cJSON_CreateArray();
    
    if (utxos) {
        for (size_t i = 0; i < count; i++) {
            cJSON *utxo_obj = cJSON_CreateObject();
            
            char txid_hex[65];
            dsv_hash_to_hex(txid_hex, &utxos[i]->txid);
            cJSON_AddStringToObject(utxo_obj, "txid", txid_hex);
            cJSON_AddNumberToObject(utxo_obj, "vout", utxos[i]->vout);
            
            char amount_str[100];
            dsv_u320_to_dec(&utxos[i]->amount, amount_str, sizeof(amount_str));
            cJSON_AddStringToObject(utxo_obj, "satoshis", amount_str);
            
            cJSON_AddNumberToObject(utxo_obj, "height", (double)utxos[i]->height);
            cJSON_AddBoolToObject(utxo_obj, "coinbase", utxos[i]->is_coinbase);
            
            cJSON_AddItemToArray(result, utxo_obj);
        }
        dsv_utxo_array_free(utxos, count);
    }
    
    return result;
}

static cJSON *rpc_getblocktemplate(dsv_rpc_server_t *server, cJSON *params,
                                    int *error_code, char **error_msg) {
    /* Get coinbase address from params if provided */
    dsv_address_t coinbase_addr;
    memset(&coinbase_addr, 0, sizeof(coinbase_addr));
    
    if (params && cJSON_IsArray(params) && cJSON_GetArraySize(params) > 0) {
        cJSON *param = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsString(param)) {
            if (!dsv_address_decode(&coinbase_addr, param->valuestring)) {
                *error_code = -32602;
                *error_msg = strdup("Invalid coinbase address");
                return NULL;
            }
        }
    }
    
    dsv_block_t *template = dsv_chain_create_block_template(server->chain, &coinbase_addr);
    if (!template) {
        *error_code = -32603;
        *error_msg = strdup("Failed to create block template");
        return NULL;
    }
    
    cJSON *result = cJSON_CreateObject();
    
    char prev_hex[65];
    dsv_hash_to_hex(prev_hex, &template->header.prev_hash);
    cJSON_AddStringToObject(result, "previousblockhash", prev_hex);
    
    cJSON_AddNumberToObject(result, "height", (double)(dsv_chain_get_height(server->chain) + 1));
    cJSON_AddNumberToObject(result, "version", template->header.version);
    cJSON_AddNumberToObject(result, "curtime", template->header.timestamp);
    
    char bits_hex[9];
    snprintf(bits_hex, sizeof(bits_hex), "%08x", template->header.bits);
    cJSON_AddStringToObject(result, "bits", bits_hex);
    
    cJSON *txs = cJSON_CreateArray();
    for (uint32_t i = 0; i < template->tx_count; i++) {
        dsv_buffer_t *buf = dsv_buffer_new(dsv_tx_serialized_size(template->txs[i]));
        dsv_tx_serialize(buf, template->txs[i]);
        
        cJSON *tx_obj = cJSON_CreateObject();
        
        char *data_hex = malloc(buf->pos * 2 + 1);
        for (size_t j = 0; j < buf->pos; j++) {
            sprintf(data_hex + j * 2, "%02x", buf->data[j]);
        }
        cJSON_AddStringToObject(tx_obj, "data", data_hex);
        free(data_hex);
        
        dsv_hash256_t txid;
        dsv_tx_compute_txid(&txid, template->txs[i]);
        char txid_hex[65];
        dsv_hash_to_hex(txid_hex, &txid);
        cJSON_AddStringToObject(tx_obj, "txid", txid_hex);
        
        cJSON_AddItemToArray(txs, tx_obj);
        dsv_buffer_free(buf);
    }
    cJSON_AddItemToObject(result, "transactions", txs);
    
    dsv_block_free(template);
    return result;
}

static cJSON *rpc_submitblock(dsv_rpc_server_t *server, cJSON *params,
                               int *error_code, char **error_msg) {
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [hexdata]");
        return NULL;
    }
    
    cJSON *hex_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(hex_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: hexdata must be string");
        return NULL;
    }
    
    const char *hex = hex_param->valuestring;
    size_t hex_len = strlen(hex);
    
    if (hex_len % 2 != 0 || hex_len > DSV_MAX_BLOCK_SIZE * 2) {
        *error_code = -22;
        *error_msg = strdup("Invalid block hex");
        return NULL;
    }
    
    /* Decode hex */
    size_t bin_len = hex_len / 2;
    uint8_t *bin = malloc(bin_len);
    if (!bin) {
        *error_code = -32603;
        *error_msg = strdup("Out of memory");
        return NULL;
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            free(bin);
            *error_code = -22;
            *error_msg = strdup("Invalid hex encoding");
            return NULL;
        }
        bin[i] = (uint8_t)byte;
    }
    
    /* Deserialize block */
    dsv_buffer_t *buf = dsv_buffer_from_data(bin, bin_len);
    dsv_block_t *block = dsv_block_deserialize(buf);
    dsv_buffer_free(buf);
    free(bin);
    
    if (!block) {
        *error_code = -22;
        *error_msg = strdup("Block decode failed");
        return NULL;
    }
    
    /* Submit block */
    int err = dsv_chain_submit_block(server->chain, block);
    dsv_block_free(block);
    
    if (err != DSV_OK && err != DSV_ERR_DUPLICATE) {
        *error_code = -1;
        *error_msg = strdup("Block rejected");
        return NULL;
    }
    
    return cJSON_CreateNull();
}

static cJSON *rpc_validateaddress(dsv_rpc_server_t *server, cJSON *params,
                                   int *error_code, char **error_msg) {
    (void)server;
    
    if (!params || !cJSON_IsArray(params) || cJSON_GetArraySize(params) < 1) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: expected [address]");
        return NULL;
    }
    
    cJSON *addr_param = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsString(addr_param)) {
        *error_code = -32602;
        *error_msg = strdup("Invalid params: address must be string");
        return NULL;
    }
    
    cJSON *result = cJSON_CreateObject();
    
    dsv_address_t addr;
    bool valid = dsv_address_decode(&addr, addr_param->valuestring);
    
    cJSON_AddBoolToObject(result, "isvalid", valid);
    if (valid) {
        cJSON_AddStringToObject(result, "address", addr_param->valuestring);
    }
    
    return result;
}

static cJSON *dispatch_method(dsv_rpc_server_t *server, const char *method,
                              cJSON *params, int *error_code, char **error_msg) {
    *error_code = 0;
    *error_msg = NULL;
    
    if (strcmp(method, RPC_GETBLOCKCHAININFO) == 0) {
        return rpc_getblockchaininfo(server);
    }
    if (strcmp(method, RPC_GETBLOCK) == 0) {
        return rpc_getblock(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_GETBLOCKHASH) == 0) {
        return rpc_getblockhash(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_GETBLOCKCOUNT) == 0) {
        return rpc_getblockcount(server);
    }
    if (strcmp(method, RPC_GETRAWTRANSACTION) == 0) {
        return rpc_getrawtransaction(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_SENDRAWTRANSACTION) == 0) {
        return rpc_sendrawtransaction(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_GETMEMPOOLINFO) == 0) {
        return rpc_getmempoolinfo(server);
    }
    if (strcmp(method, RPC_GETADDRESSBALANCE) == 0) {
        return rpc_getaddressbalance(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_GETADDRESSUTXOS) == 0) {
        return rpc_getaddressutxos(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_GETBLOCKTEMPLATE) == 0) {
        return rpc_getblocktemplate(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_SUBMITBLOCK) == 0) {
        return rpc_submitblock(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_VALIDATEADDRESS) == 0) {
        return rpc_validateaddress(server, params, error_code, error_msg);
    }
    if (strcmp(method, RPC_STOP) == 0) {
        server->should_stop = true;
        return cJSON_CreateString("DSV server stopping");
    }
    
    *error_code = -32601;
    *error_msg = strdup("Method not found");
    return NULL;
}

/* ==========================================================================
 * Server Lifecycle
 * ========================================================================== */

static void *server_thread(void *arg) {
    dsv_rpc_server_t *server = arg;
    event_base_dispatch(server->base);
    return NULL;
}

dsv_rpc_server_t *dsv_rpc_server_new(const dsv_rpc_config_t *config,
                                      dsv_chain_t *chain,
                                      dsv_mempool_t *mempool) {
    dsv_rpc_server_t *server = calloc(1, sizeof(dsv_rpc_server_t));
    if (!server) return NULL;
    
    /* Copy config */
    server->config.bind_address = config->bind_address ? strdup(config->bind_address) : strdup("127.0.0.1");
    server->config.port = config->port;
    server->config.auth_token = config->auth_token ? strdup(config->auth_token) : NULL;
    server->config.max_request_size = config->max_request_size;
    server->config.rate_limit_per_sec = config->rate_limit_per_sec;
    server->config.timeout_sec = config->timeout_sec;
    server->config.allow_remote = config->allow_remote;
    
    server->chain = chain;
    server->mempool = mempool;
    
    pthread_mutex_init(&server->rate_lock, NULL);
    
    return server;
}

int dsv_rpc_server_start(dsv_rpc_server_t *server) {
    server->base = event_base_new();
    if (!server->base) return DSV_ERR_NOMEM;
    
    server->http = evhttp_new(server->base);
    if (!server->http) {
        event_base_free(server->base);
        return DSV_ERR_NOMEM;
    }
    
    evhttp_set_timeout(server->http, server->config.timeout_sec);
    evhttp_set_max_body_size(server->http, server->config.max_request_size);
    evhttp_set_gencb(server->http, handle_request, server);
    
    if (evhttp_bind_socket(server->http, server->config.bind_address,
                           server->config.port) != 0) {
        evhttp_free(server->http);
        event_base_free(server->base);
        return DSV_ERR_NETWORK;
    }
    
    server->running = true;
    server->should_stop = false;
    
    if (pthread_create(&server->thread, NULL, server_thread, server) != 0) {
        server->running = false;
        evhttp_free(server->http);
        event_base_free(server->base);
        return DSV_ERR_NOMEM;
    }
    
    return DSV_OK;
}

void dsv_rpc_server_stop(dsv_rpc_server_t *server) {
    if (!server || !server->running) return;
    
    server->should_stop = true;
    event_base_loopbreak(server->base);
    pthread_join(server->thread, NULL);
    
    evhttp_free(server->http);
    event_base_free(server->base);
    
    server->running = false;
}

void dsv_rpc_server_free(dsv_rpc_server_t *server) {
    if (!server) return;
    
    if (server->running) {
        dsv_rpc_server_stop(server);
    }
    
    pthread_mutex_destroy(&server->rate_lock);
    dsv_rpc_config_free(&server->config);
    free(server);
}

bool dsv_rpc_server_running(dsv_rpc_server_t *server) {
    return server && server->running && !server->should_stop;
}

