/**
 * DSV CLI - Command Line Interface for DSV Node
 */

#include "dsv_types.h"
#include "dsv_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

typedef struct {
    char *rpc_url;
    char *auth_token;
} cli_config_t;

/* Response buffer */
typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;
    
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';
    
    return realsize;
}

static cJSON *rpc_call(cli_config_t *config, const char *method, cJSON *params) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    /* Build request */
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddItemToObject(request, "params", params ? params : cJSON_CreateArray());
    cJSON_AddNumberToObject(request, "id", 1);
    
    char *request_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    
    response_buffer_t response = {0};
    response.data = malloc(1);
    response.size = 0;
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    if (config->auth_token) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", config->auth_token);
        headers = curl_slist_append(headers, auth_header);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, config->rpc_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(request_str);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "RPC error: %s\n", curl_easy_strerror(res));
        free(response.data);
        return NULL;
    }
    
    cJSON *result = cJSON_Parse(response.data);
    free(response.data);
    
    return result;
}

static void print_json(cJSON *json) {
    char *str = cJSON_Print(json);
    printf("%s\n", str);
    free(str);
}

static void print_usage(const char *prog) {
    printf("DSV CLI v1.0.0\n\n");
    printf("Usage: %s [options] <command> [args...]\n\n", prog);
    printf("Options:\n");
    printf("  -r, --rpc=URL       RPC endpoint (default: http://127.0.0.1:8332)\n");
    printf("  -a, --auth=TOKEN    RPC auth token (required)\n");
    printf("  -h, --help          Show this help\n\n");
    printf("Commands:\n");
    printf("  getblockchaininfo          Get blockchain status\n");
    printf("  getblockcount              Get current block height\n");
    printf("  getblockhash <height>      Get block hash at height\n");
    printf("  getblock <hash>            Get block info\n");
    printf("  getmempoolinfo             Get mempool status\n");
    printf("  getaddressbalance <addr>   Get address balance\n");
    printf("  getaddressutxos <addr>     Get address UTXOs\n");
    printf("  validateaddress <addr>     Validate address\n");
    printf("  sendrawtransaction <hex>   Broadcast transaction\n");
    printf("  getblocktemplate           Get mining template\n");
    printf("  submitblock <hex>          Submit mined block\n");
    printf("  stop                       Stop the node\n");
}

int main(int argc, char **argv) {
    cli_config_t config = {
        .rpc_url = strdup("http://127.0.0.1:8332"),
        .auth_token = NULL
    };
    
    static struct option long_options[] = {
        {"rpc", required_argument, 0, 'r'},
        {"auth", required_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "r:a:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'r':
                free(config.rpc_url);
                config.rpc_url = strdup(optarg);
                break;
            case 'a':
                config.auth_token = strdup(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (!config.auth_token) {
        fprintf(stderr, "Error: RPC auth token required (--auth)\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    const char *command = argv[optind];
    cJSON *params = cJSON_CreateArray();
    
    /* Add remaining arguments as params */
    for (int i = optind + 1; i < argc; i++) {
        /* Try to parse as number */
        char *endptr;
        double num = strtod(argv[i], &endptr);
        if (*endptr == '\0') {
            cJSON_AddItemToArray(params, cJSON_CreateNumber(num));
        } else {
            cJSON_AddItemToArray(params, cJSON_CreateString(argv[i]));
        }
    }
    
    cJSON *response = rpc_call(&config, command, params);
    
    if (response) {
        cJSON *error = cJSON_GetObjectItem(response, "error");
        cJSON *result = cJSON_GetObjectItem(response, "result");
        
        if (error && !cJSON_IsNull(error)) {
            cJSON *message = cJSON_GetObjectItem(error, "message");
            fprintf(stderr, "Error: %s\n", 
                    message ? message->valuestring : "Unknown error");
        } else if (result) {
            print_json(result);
        }
        
        cJSON_Delete(response);
    }
    
    curl_global_cleanup();
    free(config.rpc_url);
    free(config.auth_token);
    
    return 0;
}

