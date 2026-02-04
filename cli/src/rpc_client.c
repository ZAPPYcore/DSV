/**
 * DSV CLI RPC Client
 * 
 * Handles communication with the DSV node via JSON-RPC.
 */

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define SOCKET_INVALID INVALID_SOCKET
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
typedef int socket_t;
#define SOCKET_INVALID -1
#define close_socket close
#endif

#include "rpc_client.h"

/* RPC client context */
struct dsv_rpc_client {
    char *host;
    int port;
    char *user;
    char *password;
    int timeout_ms;
    int request_id;
};

/* Initialize networking (Windows) */
static int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return 1;
#endif
}

/* Cleanup networking (Windows) */
static void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* Create RPC client */
dsv_rpc_client_t *dsv_rpc_client_new(const char *host, int port,
                                       const char *user, const char *password) {
    if (!net_init()) {
        return NULL;
    }
    
    dsv_rpc_client_t *client = calloc(1, sizeof(dsv_rpc_client_t));
    if (!client) {
        return NULL;
    }
    
    client->host = strdup(host ? host : "127.0.0.1");
    client->port = port > 0 ? port : 8332;
    client->user = user ? strdup(user) : NULL;
    client->password = password ? strdup(password) : NULL;
    client->timeout_ms = 30000;
    client->request_id = 1;
    
    return client;
}

/* Free RPC client */
void dsv_rpc_client_free(dsv_rpc_client_t *client) {
    if (!client) return;
    
    free(client->host);
    free(client->user);
    free(client->password);
    free(client);
    
    net_cleanup();
}

/* Set timeout */
void dsv_rpc_client_set_timeout(dsv_rpc_client_t *client, int timeout_ms) {
    if (client) {
        client->timeout_ms = timeout_ms;
    }
}

/* Build HTTP request with basic auth */
static char *build_http_request(dsv_rpc_client_t *client, const char *body) {
    char auth_header[256] = "";
    
    if (client->user && client->password) {
        /* Base64 encode credentials */
        char creds[256];
        snprintf(creds, sizeof(creds), "%s:%s", client->user, client->password);
        
        /* Simple base64 encoding */
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t creds_len = strlen(creds);
        char b64_creds[512];
        char *out = b64_creds;
        
        for (size_t i = 0; i < creds_len; i += 3) {
            unsigned int n = ((unsigned char)creds[i]) << 16;
            if (i + 1 < creds_len) n |= ((unsigned char)creds[i+1]) << 8;
            if (i + 2 < creds_len) n |= ((unsigned char)creds[i+2]);
            
            *out++ = b64[(n >> 18) & 63];
            *out++ = b64[(n >> 12) & 63];
            *out++ = (i + 1 < creds_len) ? b64[(n >> 6) & 63] : '=';
            *out++ = (i + 2 < creds_len) ? b64[n & 63] : '=';
        }
        *out = '\0';
        
        snprintf(auth_header, sizeof(auth_header),
                 "Authorization: Basic %s\r\n", b64_creds);
    }
    
    size_t body_len = strlen(body);
    size_t req_size = 512 + body_len + strlen(auth_header);
    char *request = malloc(req_size);
    
    if (!request) return NULL;
    
    snprintf(request, req_size,
             "POST / HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "%s"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             client->host, client->port, body_len, auth_header, body);
    
    return request;
}

/* Parse HTTP response to extract JSON body */
static char *parse_http_response(const char *response) {
    /* Find empty line separating headers from body */
    const char *body = strstr(response, "\r\n\r\n");
    if (!body) {
        body = strstr(response, "\n\n");
    }
    
    if (!body) {
        return NULL;
    }
    
    body += (body[0] == '\r') ? 4 : 2;
    
    /* Handle chunked encoding by finding JSON */
    const char *json_start = strchr(body, '{');
    if (!json_start) {
        return NULL;
    }
    
    return strdup(json_start);
}

/* Send RPC request and get response */
char *dsv_rpc_call(dsv_rpc_client_t *client, const char *method,
                    cJSON *params, dsv_rpc_error_t *error) {
    if (!client || !method) {
        if (error) {
            error->code = -1;
            error->message = strdup("Invalid arguments");
        }
        return NULL;
    }
    
    /* Build JSON-RPC request */
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddNumberToObject(request, "id", client->request_id++);
    
    if (params) {
        cJSON_AddItemToObject(request, "params", cJSON_Duplicate(params, 1));
    } else {
        cJSON_AddArrayToObject(request, "params");
    }
    
    char *json_request = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    
    if (!json_request) {
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to serialize request");
        }
        return NULL;
    }
    
    /* Build HTTP request */
    char *http_request = build_http_request(client, json_request);
    free(json_request);
    
    if (!http_request) {
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to build HTTP request");
        }
        return NULL;
    }
    
    /* Connect to server */
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SOCKET_INVALID) {
        free(http_request);
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to create socket");
        }
        return NULL;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = client->timeout_ms / 1000;
    tv.tv_usec = (client->timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    /* Resolve host */
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", client->port);
    
    if (getaddrinfo(client->host, port_str, &hints, &result) != 0) {
        close_socket(sock);
        free(http_request);
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to resolve host");
        }
        return NULL;
    }
    
    /* Connect */
    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        close_socket(sock);
        free(http_request);
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to connect");
        }
        return NULL;
    }
    freeaddrinfo(result);
    
    /* Send request */
    size_t req_len = strlen(http_request);
    if (send(sock, http_request, (int)req_len, 0) != (int)req_len) {
        close_socket(sock);
        free(http_request);
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to send request");
        }
        return NULL;
    }
    free(http_request);
    
    /* Receive response */
    char *response = malloc(65536);
    if (!response) {
        close_socket(sock);
        if (error) {
            error->code = -1;
            error->message = strdup("Out of memory");
        }
        return NULL;
    }
    
    size_t total = 0;
    int received;
    while ((received = recv(sock, response + total, 65536 - (int)total - 1, 0)) > 0) {
        total += received;
        if (total >= 65535) break;
    }
    response[total] = '\0';
    
    close_socket(sock);
    
    if (total == 0) {
        free(response);
        if (error) {
            error->code = -1;
            error->message = strdup("Empty response");
        }
        return NULL;
    }
    
    /* Parse HTTP response */
    char *json_response = parse_http_response(response);
    free(response);
    
    if (!json_response) {
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to parse HTTP response");
        }
        return NULL;
    }
    
    /* Parse JSON-RPC response */
    cJSON *json = cJSON_Parse(json_response);
    if (!json) {
        free(json_response);
        if (error) {
            error->code = -1;
            error->message = strdup("Failed to parse JSON response");
        }
        return NULL;
    }
    
    /* Check for error */
    cJSON *err = cJSON_GetObjectItem(json, "error");
    if (err && !cJSON_IsNull(err)) {
        if (error) {
            cJSON *code = cJSON_GetObjectItem(err, "code");
            cJSON *msg = cJSON_GetObjectItem(err, "message");
            error->code = code ? code->valueint : -1;
            error->message = msg ? strdup(msg->valuestring) : strdup("Unknown error");
        }
        cJSON_Delete(json);
        free(json_response);
        return NULL;
    }
    
    /* Extract result */
    cJSON *result_obj = cJSON_GetObjectItem(json, "result");
    char *result_str = NULL;
    
    if (result_obj) {
        result_str = cJSON_Print(result_obj);
    }
    
    cJSON_Delete(json);
    free(json_response);
    
    return result_str;
}

/* Convenience wrappers */

int dsv_rpc_get_block_count(dsv_rpc_client_t *client) {
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "getblockcount", NULL, &error);
    
    if (!result) {
        if (error.message) free(error.message);
        return -1;
    }
    
    int count = atoi(result);
    free(result);
    return count;
}

char *dsv_rpc_get_best_block_hash(dsv_rpc_client_t *client) {
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "getbestblockhash", NULL, &error);
    
    if (!result) {
        if (error.message) free(error.message);
        return NULL;
    }
    
    /* Remove quotes from JSON string */
    if (result[0] == '"') {
        size_t len = strlen(result);
        memmove(result, result + 1, len - 2);
        result[len - 2] = '\0';
    }
    
    return result;
}

char *dsv_rpc_get_block(dsv_rpc_client_t *client, const char *hash) {
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(hash));
    
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "getblock", params, &error);
    
    cJSON_Delete(params);
    
    if (!result && error.message) {
        free(error.message);
    }
    
    return result;
}

char *dsv_rpc_get_block_hash(dsv_rpc_client_t *client, int height) {
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateNumber(height));
    
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "getblockhash", params, &error);
    
    cJSON_Delete(params);
    
    if (!result) {
        if (error.message) free(error.message);
        return NULL;
    }
    
    /* Remove quotes from JSON string */
    if (result[0] == '"') {
        size_t len = strlen(result);
        memmove(result, result + 1, len - 2);
        result[len - 2] = '\0';
    }
    
    return result;
}

char *dsv_rpc_get_raw_transaction(dsv_rpc_client_t *client, const char *txid) {
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txid));
    cJSON_AddItemToArray(params, cJSON_CreateTrue());  /* verbose */
    
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "getrawtransaction", params, &error);
    
    cJSON_Delete(params);
    
    if (!result && error.message) {
        free(error.message);
    }
    
    return result;
}

int dsv_rpc_send_raw_transaction(dsv_rpc_client_t *client, const char *hex_tx) {
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(hex_tx));
    
    dsv_rpc_error_t error = {0};
    char *result = dsv_rpc_call(client, "sendrawtransaction", params, &error);
    
    cJSON_Delete(params);
    
    if (!result) {
        if (error.message) {
            fprintf(stderr, "Error: %s\n", error.message);
            free(error.message);
        }
        return 0;
    }
    
    free(result);
    return 1;
}

