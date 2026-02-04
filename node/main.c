/**
 * DSV Node - Main Entry Point
 * 
 * Lightweight secure blockchain node for Dynamic Storage of Value.
 */

#include "dsv_types.h"
#include "dsv_crypto.h"
#include "dsv_chain.h"
#include "dsv_mempool.h"
#include "dsv_rpc.h"
#include "dsv_p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define DSV_MKDIR(path) _mkdir(path)
#else
#define DSV_MKDIR(path) mkdir(path, 0700)
#endif

/* Global state for signal handling */
static volatile sig_atomic_t g_shutdown = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void print_usage(const char *prog) {
    printf("DSV Node v1.0.0\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -d, --datadir=DIR       Data directory (default: ~/.dsv)\n");
    printf("  -p, --port=PORT         P2P port (default: 8333)\n");
    printf("  -r, --rpcport=PORT      RPC port (default: 8332)\n");
    printf("  -a, --rpcauth=TOKEN     RPC auth token (required)\n");
    printf("  -s, --seed=HOST:PORT    Seed node (can specify multiple)\n");
    printf("  -n, --nolisten          Disable incoming P2P connections\n");
    printf("  -m, --mempool=SIZE      Mempool size in MB (default: 300)\n");
    printf("  -P, --prune=SIZE        Enable pruning, target size in MB\n");
    printf("  --rpc-allow-remote      Allow remote RPC connections\n");
    printf("  -h, --help              Show this help\n");
}

typedef struct {
    char *datadir;
    uint16_t p2p_port;
    uint16_t rpc_port;
    char *rpc_auth;
    char **seed_nodes;
    size_t seed_count;
    bool listen;
    size_t mempool_mb;
    uint64_t prune_mb;
    bool rpc_allow_remote;
} node_config_t;

static void config_free(node_config_t *config) {
    free(config->datadir);
    free(config->rpc_auth);
    if (config->seed_nodes) {
        for (size_t i = 0; i < config->seed_count; i++) {
            free(config->seed_nodes[i]);
        }
        free(config->seed_nodes);
    }
}

static void config_add_seed(node_config_t *config, const char *seed) {
    config->seed_nodes = realloc(config->seed_nodes,
                                  (config->seed_count + 1) * sizeof(char *));
    config->seed_nodes[config->seed_count++] = strdup(seed);
}

int main(int argc, char **argv) {
    node_config_t config = {0};
    
    /* Default configuration */
    const char *home = getenv("HOME");
    if (home) {
        config.datadir = malloc(strlen(home) + 10);
        sprintf(config.datadir, "%s/.dsv", home);
    } else {
        config.datadir = strdup(".dsv");
    }
    config.p2p_port = 8333;
    config.rpc_port = 8332;
    config.listen = true;
    config.mempool_mb = 300;
    config.prune_mb = 0;
    config.rpc_allow_remote = false;
    
    /* Parse command line */
    static struct option long_options[] = {
        {"datadir", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        {"rpcport", required_argument, 0, 'r'},
        {"rpcauth", required_argument, 0, 'a'},
        {"seed", required_argument, 0, 's'},
        {"nolisten", no_argument, 0, 'n'},
        {"mempool", required_argument, 0, 'm'},
        {"prune", required_argument, 0, 'P'},
        {"rpc-allow-remote", no_argument, 0, 'R'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "d:p:r:a:s:nm:P:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                free(config.datadir);
                config.datadir = strdup(optarg);
                break;
            case 'p':
                config.p2p_port = (uint16_t)atoi(optarg);
                break;
            case 'r':
                config.rpc_port = (uint16_t)atoi(optarg);
                break;
            case 'a':
                config.rpc_auth = strdup(optarg);
                break;
            case 's':
                config_add_seed(&config, optarg);
                break;
            case 'n':
                config.listen = false;
                break;
            case 'm':
                config.mempool_mb = (size_t)atoi(optarg);
                break;
            case 'P':
                config.prune_mb = (uint64_t)atoi(optarg);
                break;
            case 'R':
                config.rpc_allow_remote = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                config_free(&config);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Validate config */
    if (!config.rpc_auth) {
        fprintf(stderr, "Error: RPC auth token is required (--rpcauth)\n");
        fprintf(stderr, "Generate one with: openssl rand -hex 32\n");
        config_free(&config);
        return 1;
    }
    
    /* Initialize crypto */
    if (dsv_crypto_init() != DSV_OK) {
        fprintf(stderr, "Error: Failed to initialize cryptographic subsystem\n");
        config_free(&config);
        return 1;
    }
    
    /* Create data directory */
    DSV_MKDIR(config.datadir);
    
    printf("DSV Node starting...\n");
    printf("  Data directory: %s\n", config.datadir);
    printf("  P2P port: %u\n", config.p2p_port);
    printf("  RPC port: %u\n", config.rpc_port);
    printf("  Mempool: %zu MB\n", config.mempool_mb);
    if (config.prune_mb > 0) {
        printf("  Pruning: enabled (target %llu MB)\n", (unsigned long long)config.prune_mb);
    }
    
    /* Initialize chain */
    printf("Initializing blockchain...\n");
    dsv_chain_t *chain = dsv_chain_new(config.datadir);
    if (!chain) {
        fprintf(stderr, "Error: Failed to initialize blockchain\n");
        config_free(&config);
        return 1;
    }
    
    printf("  Best height: %lld\n", (long long)dsv_chain_get_height(chain));
    
    /* Initialize mempool */
    printf("Initializing mempool...\n");
    dsv_mempool_t *mempool = dsv_mempool_new(config.mempool_mb);
    if (!mempool) {
        fprintf(stderr, "Error: Failed to initialize mempool\n");
        dsv_chain_free(chain);
        config_free(&config);
        return 1;
    }
    
    dsv_chain_set_mempool(chain, mempool);
    
    /* Initialize RPC server */
    printf("Starting RPC server on port %u...\n", config.rpc_port);
    
    dsv_rpc_config_t rpc_config = dsv_rpc_default_config();
    rpc_config.port = config.rpc_port;
    free(rpc_config.auth_token);
    rpc_config.auth_token = strdup(config.rpc_auth);
    rpc_config.allow_remote = config.rpc_allow_remote;
    
    dsv_rpc_server_t *rpc = dsv_rpc_server_new(&rpc_config, chain, mempool);
    if (!rpc) {
        fprintf(stderr, "Error: Failed to create RPC server\n");
        dsv_mempool_free(mempool);
        dsv_chain_free(chain);
        config_free(&config);
        dsv_rpc_config_free(&rpc_config);
        return 1;
    }
    
    if (dsv_rpc_server_start(rpc) != DSV_OK) {
        fprintf(stderr, "Error: Failed to start RPC server\n");
        dsv_rpc_server_free(rpc);
        dsv_mempool_free(mempool);
        dsv_chain_free(chain);
        config_free(&config);
        dsv_rpc_config_free(&rpc_config);
        return 1;
    }
    
    dsv_rpc_config_free(&rpc_config);
    
    /* Initialize P2P network */
    printf("Starting P2P network on port %u...\n", config.p2p_port);
    
    dsv_p2p_config_t p2p_config = dsv_p2p_default_config();
    p2p_config.port = config.p2p_port;
    p2p_config.enable_listen = config.listen;
    p2p_config.seed_nodes = config.seed_nodes;
    p2p_config.seed_node_count = config.seed_count;
    
    dsv_p2p_t *p2p = dsv_p2p_new(&p2p_config, chain, mempool);
    if (!p2p) {
        fprintf(stderr, "Error: Failed to create P2P network\n");
        dsv_rpc_server_free(rpc);
        dsv_mempool_free(mempool);
        dsv_chain_free(chain);
        config_free(&config);
        return 1;
    }
    
    /* Don't free p2p_config seed_nodes - they're shared with config */
    p2p_config.seed_nodes = NULL;
    p2p_config.seed_node_count = 0;
    dsv_p2p_config_free(&p2p_config);
    
    if (dsv_p2p_start(p2p) != DSV_OK) {
        fprintf(stderr, "Warning: Failed to start P2P network\n");
        /* Continue without P2P */
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("\nDSV Node running. Press Ctrl+C to stop.\n\n");
    
    /* Main loop */
    while (!g_shutdown && dsv_rpc_server_running(rpc)) {
        sleep(1);
        
        /* Periodic status */
        static int status_counter = 0;
        if (++status_counter >= 60) {
            status_counter = 0;
            printf("Status: height=%lld, peers=%d, mempool=%zu\n",
                   (long long)dsv_chain_get_height(chain),
                   dsv_p2p_peer_count(p2p),
                   dsv_mempool_size(mempool));
        }
    }
    
    /* Shutdown */
    printf("\nShutting down...\n");
    
    dsv_p2p_stop(p2p);
    dsv_p2p_free(p2p);
    
    dsv_rpc_server_stop(rpc);
    dsv_rpc_server_free(rpc);
    
    dsv_mempool_free(mempool);
    dsv_chain_free(chain);
    
    config_free(&config);
    
    printf("DSV Node stopped.\n");
    return 0;
}

