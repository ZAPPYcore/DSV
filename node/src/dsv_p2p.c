/**
 * DSV P2P Network Implementation
 *
 * Simple TCP-based peer-to-peer network.
 */

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  /* MinGW에서는 winsock 헤더가 windows.h보다 먼저 와야 안전함 */
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

#include "dsv_p2p.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

/* Protocol constants */
#define PROTOCOL_VERSION    70015
#define NETWORK_MAGIC       0x44535600  /* "DSV\0" */
#define MAX_MESSAGE_SIZE    (4 * 1024 * 1024)  /* 4 MB */
#define HEADER_SIZE         24

/* Message header */
typedef struct {
    uint32_t magic;
    char command[12];
    uint32_t length;
    uint32_t checksum;
} msg_header_t;

/* Peer state */
typedef enum {
    PEER_CONNECTING,
    PEER_CONNECTED,
    PEER_READY,
    PEER_DISCONNECTING
} peer_state_t;

typedef struct dsv_peer_s {
    struct bufferevent *bev;
    char address[64];
    uint16_t port;
    peer_state_t state;
    bool inbound;
    int64_t version;
    int64_t best_height;
    time_t connected_at;
    time_t last_recv;
    time_t last_send;
    uint8_t recv_buffer[MAX_MESSAGE_SIZE + HEADER_SIZE];
    size_t recv_pos;
    struct dsv_peer_s *next;
} dsv_peer_t;

struct dsv_p2p_s {
    dsv_p2p_config_t config;
    dsv_chain_t *chain;
    dsv_mempool_t *mempool;
    
    struct event_base *base;
    struct evconnlistener *listener;
    pthread_t thread;
    bool running;
    bool should_stop;
    
    dsv_peer_t *peers;
    int peer_count;
    pthread_mutex_t peers_lock;
    
    /* Known addresses for peer discovery */
    char **known_addrs;
    size_t known_addr_count;
};

/* Forward declarations */
static void peer_read_cb(struct bufferevent *bev, void *ctx);
static void peer_event_cb(struct bufferevent *bev, short events, void *ctx);
static void handle_message(dsv_p2p_t *p2p, dsv_peer_t *peer,
                           const char *command, const uint8_t *payload, size_t len);

/* ==========================================================================
 * Configuration
 * ========================================================================== */

dsv_p2p_config_t dsv_p2p_default_config(void) {
    dsv_p2p_config_t config;
    memset(&config, 0, sizeof(config));
    config.bind_address = strdup("0.0.0.0");
    config.port = 8333;
    config.max_peers = 125;
    config.max_outbound = 8;
    config.seed_nodes = NULL;
    config.seed_node_count = 0;
    config.enable_listen = true;
    return config;
}

void dsv_p2p_config_free(dsv_p2p_config_t *config) {
    if (!config) return;
    free(config->bind_address);
    if (config->seed_nodes) {
        for (size_t i = 0; i < config->seed_node_count; i++) {
            free(config->seed_nodes[i]);
        }
        free(config->seed_nodes);
    }
}

/* ==========================================================================
 * Peer Management
 * ========================================================================== */

static dsv_peer_t *peer_new(dsv_p2p_t *p2p, struct bufferevent *bev,
                            const char *address, uint16_t port, bool inbound) {
    dsv_peer_t *peer = calloc(1, sizeof(dsv_peer_t));
    if (!peer) return NULL;
    
    peer->bev = bev;
    strncpy(peer->address, address, sizeof(peer->address) - 1);
    peer->port = port;
    peer->state = PEER_CONNECTING;
    peer->inbound = inbound;
    peer->connected_at = time(NULL);
    peer->last_recv = peer->connected_at;
    peer->last_send = peer->connected_at;
    
    /* Add to peer list */
    pthread_mutex_lock(&p2p->peers_lock);
    peer->next = p2p->peers;
    p2p->peers = peer;
    p2p->peer_count++;
    pthread_mutex_unlock(&p2p->peers_lock);
    
    return peer;
}

static void peer_free(dsv_p2p_t *p2p, dsv_peer_t *peer) {
    if (!peer) return;
    
    /* Remove from peer list */
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t **pp = &p2p->peers;
    while (*pp) {
        if (*pp == peer) {
            *pp = peer->next;
            p2p->peer_count--;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
    
    if (peer->bev) {
        bufferevent_free(peer->bev);
    }
    free(peer);
}

static dsv_peer_t *find_peer_by_bev(dsv_p2p_t *p2p, struct bufferevent *bev) {
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t *peer = p2p->peers;
    while (peer) {
        if (peer->bev == bev) {
            pthread_mutex_unlock(&p2p->peers_lock);
            return peer;
        }
        peer = peer->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
    return NULL;
}

/* ==========================================================================
 * Message Serialization
 * ========================================================================== */

static void send_message(dsv_peer_t *peer, const char *command,
                         const uint8_t *payload, size_t len) {
    if (!peer || !peer->bev) return;
    
    msg_header_t header;
    header.magic = NETWORK_MAGIC;
    memset(header.command, 0, sizeof(header.command));
    memset(header.command, 0, sizeof(header.command));
    strncpy(header.command, command, sizeof(header.command) - 1);

    header.length = (uint32_t)len;
    
    /* Checksum is first 4 bytes of double SHA-256 */
    dsv_hash256_t hash;
    if (len > 0) {
        dsv_hash256(&hash, payload, len);
    } else {
        uint8_t empty[1] = {0};
        dsv_hash256(&hash, empty, 0);
    }
    memcpy(&header.checksum, hash.data, 4);
    
    struct evbuffer *output = bufferevent_get_output(peer->bev);
    evbuffer_add(output, &header, HEADER_SIZE);
    if (len > 0) {
        evbuffer_add(output, payload, len);
    }
    
    peer->last_send = time(NULL);
}

/* ==========================================================================
 * Protocol Messages
 * ========================================================================== */

static void send_version(dsv_p2p_t *p2p, dsv_peer_t *peer) {
    dsv_buffer_t *buf = dsv_buffer_new(256);
    if (!buf) return;
    
    /* Version message format */
    dsv_write_u32(buf, PROTOCOL_VERSION);
    dsv_write_u64(buf, 1);  /* Services: NODE_NETWORK */
    dsv_write_u64(buf, (uint64_t)time(NULL));  /* Timestamp */
    
    /* Addr recv */
    dsv_write_u64(buf, 1);  /* Services */
    uint8_t ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
    dsv_write_bytes(buf, ipv6, 16);
    dsv_write_u16(buf, htons(peer->port));
    
    /* Addr from */
    dsv_write_u64(buf, 1);
    dsv_write_bytes(buf, ipv6, 16);
    dsv_write_u16(buf, htons(p2p->config.port));
    
    /* Nonce */
    dsv_write_u64(buf, dsv_random_u64());
    
    /* User agent */
    const char *ua = "/DSV:1.0.0/";
    dsv_write_varint(buf, strlen(ua));
    dsv_write_bytes(buf, (const uint8_t *)ua, strlen(ua));
    
    /* Start height */
    dsv_write_u32(buf, (uint32_t)dsv_chain_get_height(p2p->chain));
    
    /* Relay */
    dsv_write_u8(buf, 1);
    
    send_message(peer, MSG_VERSION, buf->data, buf->pos);
    dsv_buffer_free(buf);
}

static void send_verack(dsv_peer_t *peer) {
    send_message(peer, MSG_VERACK, NULL, 0);
}

#if defined(__GNUC__)
__attribute__((unused))
#endif
static void send_ping(dsv_peer_t *peer) {
    uint64_t nonce = dsv_random_u64();
    send_message(peer, MSG_PING, (uint8_t *)&nonce, 8);
}

static void send_pong(dsv_peer_t *peer, uint64_t nonce) {
    send_message(peer, MSG_PONG, (uint8_t *)&nonce, 8);
}

static void send_getblocks(dsv_p2p_t *p2p, dsv_peer_t *peer) {
    dsv_buffer_t *buf = dsv_buffer_new(256);
    if (!buf) return;
    
    dsv_write_u32(buf, PROTOCOL_VERSION);
    
    /* Block locator hashes - simplified, just send best block */
    dsv_write_varint(buf, 1);
    dsv_hash256_t best_hash;
    dsv_chain_get_best_hash(p2p->chain, &best_hash);
    dsv_write_hash(buf, &best_hash);
    
    /* Hash stop (all zeros = get as many as possible) */
    dsv_write_hash(buf, &DSV_HASH_ZERO);
    
    send_message(peer, MSG_GETBLOCKS, buf->data, buf->pos);
    dsv_buffer_free(buf);
}

static void send_inv(dsv_peer_t *peer, int type, const dsv_hash256_t *hash) {
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) return;
    
    dsv_write_varint(buf, 1);  /* Count */
    dsv_write_u32(buf, type);
    dsv_write_hash(buf, hash);
    
    send_message(peer, MSG_INV, buf->data, buf->pos);
    dsv_buffer_free(buf);
}

static void send_getdata(dsv_peer_t *peer, int type, const dsv_hash256_t *hash) {
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) return;
    
    dsv_write_varint(buf, 1);
    dsv_write_u32(buf, type);
    dsv_write_hash(buf, hash);
    
    send_message(peer, MSG_GETDATA, buf->data, buf->pos);
    dsv_buffer_free(buf);
}

/* ==========================================================================
 * Message Handling
 * ========================================================================== */

static void handle_version(dsv_p2p_t *p2p, dsv_peer_t *peer,
                           const uint8_t *payload, size_t len) {
    (void)p2p;
    
    if (len < 85) return;
    
    dsv_buffer_t *buf = dsv_buffer_from_data(payload, len);
    if (!buf) return;
    
    uint32_t version;
    dsv_read_u32(buf, &version);
    peer->version = version;
    
    /* Skip services, timestamp, addr_recv, addr_from, nonce */
    buf->pos += 8 + 8 + 26 + 26 + 8;
    
    /* Skip user agent */
    uint64_t ua_len;
    dsv_read_varint(buf, &ua_len);
    buf->pos += ua_len;
    
    /* Start height */
    uint32_t height;
    dsv_read_u32(buf, &height);
    peer->best_height = height;
    
    dsv_buffer_free(buf);
    
    /* Send verack */
    send_verack(peer);
    
    /* If we initiated, send our version */
    if (!peer->inbound && peer->state == PEER_CONNECTING) {
        send_version(p2p, peer);
    }
    
    peer->state = PEER_CONNECTED;
}

static void handle_verack(dsv_p2p_t *p2p, dsv_peer_t *peer) {
    peer->state = PEER_READY;
    
    /* Start sync if needed */
    int64_t our_height = dsv_chain_get_height(p2p->chain);
    if (peer->best_height > our_height) {
        send_getblocks(p2p, peer);
    }
}

static void handle_ping(dsv_peer_t *peer, const uint8_t *payload, size_t len) {
    if (len >= 8) {
        uint64_t nonce;
        memcpy(&nonce, payload, 8);
        send_pong(peer, nonce);
    }
}

static void handle_inv(dsv_p2p_t *p2p, dsv_peer_t *peer,
                       const uint8_t *payload, size_t len) {
    dsv_buffer_t *buf = dsv_buffer_from_data(payload, len);
    if (!buf) return;
    
    uint64_t count;
    dsv_read_varint(buf, &count);
    
    for (uint64_t i = 0; i < count && dsv_buffer_remaining(buf) >= 36; i++) {
        uint32_t type;
        dsv_hash256_t hash;
        dsv_read_u32(buf, &type);
        dsv_read_hash(buf, &hash);
        
        if (type == INV_BLOCK) {
            /* Check if we have this block */
            dsv_block_index_t *idx = dsv_chain_get_block_index(p2p->chain, &hash);
            if (!idx) {
                /* Request it */
                send_getdata(peer, INV_BLOCK, &hash);
            } else {
                dsv_block_index_free(idx);
            }
        } else if (type == INV_TX) {
            /* Check if we have this tx */
            if (p2p->mempool && !dsv_mempool_contains(p2p->mempool, &hash)) {
                send_getdata(peer, INV_TX, &hash);
            }
        }
    }
    
    dsv_buffer_free(buf);
}

static void handle_block(dsv_p2p_t *p2p, const uint8_t *payload, size_t len) {
    dsv_buffer_t *buf = dsv_buffer_from_data(payload, len);
    if (!buf) return;
    
    dsv_block_t *block = dsv_block_deserialize(buf);
    dsv_buffer_free(buf);
    
    if (block) {
        dsv_chain_accept_block(p2p->chain, block);
        dsv_block_free(block);
    }
}

static void handle_tx(dsv_p2p_t *p2p, const uint8_t *payload, size_t len) {
    if (!p2p->mempool) return;
    
    dsv_buffer_t *buf = dsv_buffer_from_data(payload, len);
    if (!buf) return;
    
    dsv_tx_t *tx = dsv_tx_deserialize(buf);
    dsv_buffer_free(buf);
    
    if (tx) {
        dsv_u320_t fee;
        int err = dsv_chain_validate_tx(p2p->chain, tx, &fee);
        if (err == DSV_OK) {
            dsv_mempool_add(p2p->mempool, tx, &fee);
        }
        dsv_tx_free(tx);
    }
}

static void handle_message(dsv_p2p_t *p2p, dsv_peer_t *peer,
                           const char *command, const uint8_t *payload, size_t len) {
    peer->last_recv = time(NULL);
    
    if (strcmp(command, MSG_VERSION) == 0) {
        handle_version(p2p, peer, payload, len);
    } else if (strcmp(command, MSG_VERACK) == 0) {
        handle_verack(p2p, peer);
    } else if (strcmp(command, MSG_PING) == 0) {
        handle_ping(peer, payload, len);
    } else if (strcmp(command, MSG_PONG) == 0) {
        /* Ignore pong */
    } else if (strcmp(command, MSG_INV) == 0) {
        handle_inv(p2p, peer, payload, len);
    } else if (strcmp(command, MSG_BLOCK) == 0) {
        handle_block(p2p, payload, len);
    } else if (strcmp(command, MSG_TX) == 0) {
        handle_tx(p2p, payload, len);
    }
    /* Other messages ignored for now */
}

/* ==========================================================================
 * Network I/O Callbacks
 * ========================================================================== */

static void peer_read_cb(struct bufferevent *bev, void *ctx) {
    dsv_p2p_t *p2p = ctx;
    dsv_peer_t *peer = find_peer_by_bev(p2p, bev);
    if (!peer) return;
    
    struct evbuffer *input = bufferevent_get_input(bev);
    
    while (evbuffer_get_length(input) > 0) {
        size_t needed = HEADER_SIZE;
        
        if (peer->recv_pos >= HEADER_SIZE) {
            msg_header_t *hdr = (msg_header_t *)peer->recv_buffer;
            needed = HEADER_SIZE + hdr->length;
        }
        
        size_t available = evbuffer_get_length(input);
        size_t to_copy = needed - peer->recv_pos;
        if (to_copy > available) to_copy = available;
        
        if (peer->recv_pos + to_copy > sizeof(peer->recv_buffer)) {
            /* Message too large, disconnect */
            peer->state = PEER_DISCONNECTING;
            return;
        }
        
        evbuffer_remove(input, peer->recv_buffer + peer->recv_pos, to_copy);
        peer->recv_pos += to_copy;
        
        if (peer->recv_pos >= HEADER_SIZE) {
            msg_header_t *hdr = (msg_header_t *)peer->recv_buffer;
            
            /* Validate magic */
            if (hdr->magic != NETWORK_MAGIC) {
                peer->state = PEER_DISCONNECTING;
                return;
            }
            
            /* Check if message complete */
            if (peer->recv_pos >= HEADER_SIZE + hdr->length) {
                /* Validate checksum */
                dsv_hash256_t hash;
                dsv_hash256(&hash, peer->recv_buffer + HEADER_SIZE, hdr->length);
                if (memcmp(hash.data, &hdr->checksum, 4) != 0) {
                    /* Bad checksum, skip message */
                    peer->recv_pos = 0;
                    continue;
                }
                
                /* Handle message */
                char command[13] = {0};
                memcpy(command, hdr->command, 12);
                handle_message(p2p, peer, command,
                              peer->recv_buffer + HEADER_SIZE, hdr->length);
                
                /* Reset for next message */
                peer->recv_pos = 0;
            }
        }
    }
}

static void peer_event_cb(struct bufferevent *bev, short events, void *ctx) {
    dsv_p2p_t *p2p = ctx;
    dsv_peer_t *peer = find_peer_by_bev(p2p, bev);
    
    if (events & BEV_EVENT_CONNECTED) {
        if (peer && !peer->inbound) {
            send_version(p2p, peer);
        }
    }
    
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (peer) {
            peer_free(p2p, peer);
        }
    }
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *ctx) {
    (void)listener;
    (void)socklen;
    
    dsv_p2p_t *p2p = ctx;
    
    /* Check peer limit */
    if (p2p->peer_count >= p2p->config.max_peers) {
        evutil_closesocket(fd);
        return;
    }
    
    struct bufferevent *bev = bufferevent_socket_new(p2p->base, fd,
        BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        evutil_closesocket(fd);
        return;
    }
    
    /* Get peer address */
    char addr_str[64] = "unknown";
    uint16_t port = 0;
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        port = ntohs(sin->sin_port);
    }
    
    dsv_peer_t *peer = peer_new(p2p, bev, addr_str, port, true);
    if (!peer) {
        bufferevent_free(bev);
        return;
    }
    
    bufferevent_setcb(bev, peer_read_cb, NULL, peer_event_cb, p2p);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    
    /* Send version */
    send_version(p2p, peer);
}

/* ==========================================================================
 * Connection Management
 * ========================================================================== */

static int connect_to_peer(dsv_p2p_t *p2p, const char *address, uint16_t port) {
    struct bufferevent *bev = bufferevent_socket_new(p2p->base, -1,
        BEV_OPT_CLOSE_ON_FREE);
    if (!bev) return DSV_ERR_NOMEM;
    
    dsv_peer_t *peer = peer_new(p2p, bev, address, port, false);
    if (!peer) {
        bufferevent_free(bev);
        return DSV_ERR_NOMEM;
    }
    
    bufferevent_setcb(bev, peer_read_cb, NULL, peer_event_cb, p2p);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, address, &sin.sin_addr);
    
    if (bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        peer_free(p2p, peer);
        return DSV_ERR_NETWORK;
    }
    
    return DSV_OK;
}

/* ==========================================================================
 * P2P Network Lifecycle
 * ========================================================================== */

static void *p2p_thread(void *arg) {
    dsv_p2p_t *p2p = arg;
    event_base_dispatch(p2p->base);
    return NULL;
}

dsv_p2p_t *dsv_p2p_new(const dsv_p2p_config_t *config,
                        dsv_chain_t *chain,
                        dsv_mempool_t *mempool) {
    dsv_p2p_t *p2p = calloc(1, sizeof(dsv_p2p_t));
    if (!p2p) return NULL;
    
    /* Copy config */
    p2p->config.bind_address = config->bind_address ? strdup(config->bind_address) : strdup("0.0.0.0");
    p2p->config.port = config->port;
    p2p->config.max_peers = config->max_peers;
    p2p->config.max_outbound = config->max_outbound;
    p2p->config.enable_listen = config->enable_listen;
    
    if (config->seed_nodes && config->seed_node_count > 0) {
        p2p->config.seed_nodes = malloc(config->seed_node_count * sizeof(char *));
        p2p->config.seed_node_count = config->seed_node_count;
        for (size_t i = 0; i < config->seed_node_count; i++) {
            p2p->config.seed_nodes[i] = strdup(config->seed_nodes[i]);
        }
    }
    
    p2p->chain = chain;
    p2p->mempool = mempool;
    
    pthread_mutex_init(&p2p->peers_lock, NULL);
    
    return p2p;
}

int dsv_p2p_start(dsv_p2p_t *p2p) {
    p2p->base = event_base_new();
    if (!p2p->base) return DSV_ERR_NOMEM;
    
    /* Start listener if enabled */
    if (p2p->config.enable_listen) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(p2p->config.port);
        inet_pton(AF_INET, p2p->config.bind_address, &sin.sin_addr);
        
        p2p->listener = evconnlistener_new_bind(p2p->base, accept_conn_cb, p2p,
            LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
            (struct sockaddr *)&sin, sizeof(sin));
        
        if (!p2p->listener) {
            event_base_free(p2p->base);
            return DSV_ERR_NETWORK;
        }
    }
    
    p2p->running = true;
    p2p->should_stop = false;
    
    /* Connect to seed nodes */
    for (size_t i = 0; i < p2p->config.seed_node_count; i++) {
        /* Parse address:port */
        char addr[64];
        uint16_t port = p2p->config.port;
        
        strncpy(addr, p2p->config.seed_nodes[i], sizeof(addr) - 1);
        char *colon = strchr(addr, ':');
        if (colon) {
            *colon = '\0';
            port = (uint16_t)atoi(colon + 1);
        }
        
        connect_to_peer(p2p, addr, port);
    }
    
    /* Start event loop */
    if (pthread_create(&p2p->thread, NULL, p2p_thread, p2p) != 0) {
        if (p2p->listener) evconnlistener_free(p2p->listener);
        event_base_free(p2p->base);
        return DSV_ERR_NOMEM;
    }
    
    return DSV_OK;
}

void dsv_p2p_stop(dsv_p2p_t *p2p) {
    if (!p2p || !p2p->running) return;
    
    p2p->should_stop = true;
    event_base_loopbreak(p2p->base);
    pthread_join(p2p->thread, NULL);
    
    /* Disconnect all peers */
    pthread_mutex_lock(&p2p->peers_lock);
    while (p2p->peers) {
        dsv_peer_t *peer = p2p->peers;
        p2p->peers = peer->next;
        if (peer->bev) bufferevent_free(peer->bev);
        free(peer);
    }
    p2p->peer_count = 0;
    pthread_mutex_unlock(&p2p->peers_lock);
    
    if (p2p->listener) evconnlistener_free(p2p->listener);
    event_base_free(p2p->base);
    
    p2p->running = false;
}

void dsv_p2p_free(dsv_p2p_t *p2p) {
    if (!p2p) return;
    
    if (p2p->running) {
        dsv_p2p_stop(p2p);
    }
    
    pthread_mutex_destroy(&p2p->peers_lock);
    dsv_p2p_config_free(&p2p->config);
    
    for (size_t i = 0; i < p2p->known_addr_count; i++) {
        free(p2p->known_addrs[i]);
    }
    free(p2p->known_addrs);
    
    free(p2p);
}

int dsv_p2p_peer_count(dsv_p2p_t *p2p) {
    pthread_mutex_lock(&p2p->peers_lock);
    int count = p2p->peer_count;
    pthread_mutex_unlock(&p2p->peers_lock);
    return count;
}

void dsv_p2p_broadcast_tx(dsv_p2p_t *p2p, const dsv_hash256_t *txid) {
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t *peer = p2p->peers;
    while (peer) {
        if (peer->state == PEER_READY) {
            send_inv(peer, INV_TX, txid);
        }
        peer = peer->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
}

void dsv_p2p_broadcast_block(dsv_p2p_t *p2p, const dsv_hash256_t *hash) {
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t *peer = p2p->peers;
    while (peer) {
        if (peer->state == PEER_READY) {
            send_inv(peer, INV_BLOCK, hash);
        }
        peer = peer->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
}

void dsv_p2p_request_block(dsv_p2p_t *p2p, const dsv_hash256_t *hash) {
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t *peer = p2p->peers;
    while (peer) {
        if (peer->state == PEER_READY) {
            send_getdata(peer, INV_BLOCK, hash);
            break;  /* Request from one peer */
        }
        peer = peer->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
}

bool dsv_p2p_is_synced(dsv_p2p_t *p2p) {
    int64_t our_height = dsv_chain_get_height(p2p->chain);
    
    pthread_mutex_lock(&p2p->peers_lock);
    dsv_peer_t *peer = p2p->peers;
    int64_t max_peer_height = 0;
    while (peer) {
        if (peer->state == PEER_READY && peer->best_height > max_peer_height) {
            max_peer_height = peer->best_height;
        }
        peer = peer->next;
    }
    pthread_mutex_unlock(&p2p->peers_lock);
    
    /* Consider synced if within 2 blocks of best peer */
    return our_height >= max_peer_height - 2;
}

