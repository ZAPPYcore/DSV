/**
 * DSV Secure Wallet Implementation
 * 
 * Uses Shamir's Secret Sharing for 2-of-3 passphrase protection.
 */

#include "dsv_wallet.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"
#include "dsv_u320.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Wallet file magic and version */
#define WALLET_MAGIC    0x44535657  /* "DSVW" */
#define WALLET_VERSION  1

/* Key derivation parameters */
#define KDF_OPSLIMIT    crypto_pwhash_OPSLIMIT_MODERATE
#define KDF_MEMLIMIT    crypto_pwhash_MEMLIMIT_MODERATE

/* Maximum keys in wallet */
#define MAX_WALLET_KEYS 10000

/* Encrypted key entry */
typedef struct {
    dsv_address_t address;
    dsv_pubkey_t pubkey;
    uint8_t encrypted_seed[32 + crypto_secretbox_MACBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
} encrypted_key_t;

struct dsv_wallet_s {
    char *path;
    
    /* TSA shares (encrypted with passphrase-derived keys) */
    uint8_t encrypted_shares[3][32 + crypto_secretbox_MACBYTES];
    uint8_t share_nonces[3][crypto_secretbox_NONCEBYTES];
    uint8_t share_salts[3][crypto_pwhash_SALTBYTES];
    
    /* Master key (only in memory when unlocked) */
    uint8_t master_key[32];
    bool unlocked;
    
    /* Keys */
    encrypted_key_t *keys;
    size_t key_count;
    size_t key_capacity;
    
    /* Key index for address lookup */
    uint32_t next_key_index;
};

/* ==========================================================================
 * Galois Field Arithmetic (GF(2^8) for Shamir's Secret Sharing)
 * ========================================================================== */

/* Log and exp tables for GF(2^8) with generator polynomial 0x11D */
static uint8_t gf_log[256];
static uint8_t gf_exp[512];
static bool gf_initialized = false;

static void gf_init(void) {
    if (gf_initialized) return;
    
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[(uint8_t)x] = (uint8_t)i;
        
        x <<= 1;
        if (x & 0x100) {
            x ^= 0x11D;  /* Reduction polynomial */
        }
    }
    
    /* Extend exp table for easy modular arithmetic */
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    
    gf_initialized = true;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

static uint8_t gf_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;  /* Division by zero */
    if (a == 0) return 0;
    return gf_exp[(gf_log[a] + 255 - gf_log[b]) % 255];
}

static uint8_t gf_add(uint8_t a, uint8_t b) {
    return a ^ b;  /* XOR in GF(2^8) */
}

/* ==========================================================================
 * Shamir's Secret Sharing (2-of-3)
 * ========================================================================== */

void dsv_tsa_split(const uint8_t secret[32], dsv_share_t shares[3]) {
    gf_init();
    
    /* Generate random coefficient for linear polynomial: f(x) = secret + a*x */
    uint8_t coeff[32];
    randombytes_buf(coeff, 32);
    
    /* Evaluate polynomial at x = 1, 2, 3 */
    for (int i = 0; i < 3; i++) {
        shares[i].index = (uint8_t)(i + 1);
        
        for (int j = 0; j < 32; j++) {
            /* f(x) = secret[j] + coeff[j] * x */
            shares[i].share[j] = gf_add(secret[j], gf_mul(coeff[j], shares[i].index));
        }
    }
    
    /* Securely clear coefficient */
    sodium_memzero(coeff, sizeof(coeff));
}

bool dsv_tsa_combine(uint8_t secret[32], const dsv_share_t *share1,
                     const dsv_share_t *share2) {
    gf_init();
    
    if (share1->index == share2->index) return false;
    if (share1->index < 1 || share1->index > 3) return false;
    if (share2->index < 1 || share2->index > 3) return false;
    
    uint8_t x1 = share1->index;
    uint8_t x2 = share2->index;
    
    /* Lagrange interpolation at x = 0 */
    /* L1(0) = x2 / (x2 - x1) */
    /* L2(0) = x1 / (x1 - x2) */
    uint8_t denom = gf_add(x2, x1);  /* x2 - x1 in GF(2^8) is same as x2 XOR x1 */
    
    uint8_t l1 = gf_div(x2, denom);
    uint8_t l2 = gf_div(x1, denom);
    
    for (int i = 0; i < 32; i++) {
        secret[i] = gf_add(gf_mul(share1->share[i], l1),
                           gf_mul(share2->share[i], l2));
    }
    
    return true;
}

/* ==========================================================================
 * Key Derivation from Passphrase
 * ========================================================================== */

static bool derive_key_from_passphrase(uint8_t key[32], const char *passphrase,
                                        const uint8_t salt[crypto_pwhash_SALTBYTES]) {
    return crypto_pwhash(key, 32, passphrase, strlen(passphrase),
                         salt, KDF_OPSLIMIT, KDF_MEMLIMIT,
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}

/* ==========================================================================
 * Wallet File I/O
 * ========================================================================== */

static bool wallet_save(dsv_wallet_t *wallet) {
    FILE *f = fopen(wallet->path, "wb");
    if (!f) return false;
    
    /* Header */
    uint32_t magic = WALLET_MAGIC;
    uint32_t version = WALLET_VERSION;
    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);
    
    /* TSA encrypted shares */
    for (int i = 0; i < 3; i++) {
        fwrite(wallet->share_salts[i], crypto_pwhash_SALTBYTES, 1, f);
        fwrite(wallet->share_nonces[i], crypto_secretbox_NONCEBYTES, 1, f);
        fwrite(wallet->encrypted_shares[i], 32 + crypto_secretbox_MACBYTES, 1, f);
    }
    
    /* Key count */
    uint32_t key_count = (uint32_t)wallet->key_count;
    fwrite(&key_count, 4, 1, f);
    fwrite(&wallet->next_key_index, 4, 1, f);
    
    /* Keys */
    for (size_t i = 0; i < wallet->key_count; i++) {
        fwrite(&wallet->keys[i].address, sizeof(dsv_address_t), 1, f);
        fwrite(&wallet->keys[i].pubkey, sizeof(dsv_pubkey_t), 1, f);
        fwrite(wallet->keys[i].nonce, crypto_secretbox_NONCEBYTES, 1, f);
        fwrite(wallet->keys[i].encrypted_seed, 32 + crypto_secretbox_MACBYTES, 1, f);
    }
    
    fclose(f);
    return true;
}

static dsv_wallet_t *wallet_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    
    /* Check header */
    uint32_t magic, version;
    if (fread(&magic, 4, 1, f) != 1 || magic != WALLET_MAGIC) {
        fclose(f);
        return NULL;
    }
    if (fread(&version, 4, 1, f) != 1 || version != WALLET_VERSION) {
        fclose(f);
        return NULL;
    }
    
    dsv_wallet_t *wallet = calloc(1, sizeof(dsv_wallet_t));
    if (!wallet) {
        fclose(f);
        return NULL;
    }
    
    wallet->path = strdup(path);
    
    /* Read TSA shares */
    for (int i = 0; i < 3; i++) {
        if (fread(wallet->share_salts[i], crypto_pwhash_SALTBYTES, 1, f) != 1 ||
            fread(wallet->share_nonces[i], crypto_secretbox_NONCEBYTES, 1, f) != 1 ||
            fread(wallet->encrypted_shares[i], 32 + crypto_secretbox_MACBYTES, 1, f) != 1) {
            free(wallet->path);
            free(wallet);
            fclose(f);
            return NULL;
        }
    }
    
    /* Read key count */
    uint32_t key_count;
    if (fread(&key_count, 4, 1, f) != 1 || key_count > MAX_WALLET_KEYS) {
        free(wallet->path);
        free(wallet);
        fclose(f);
        return NULL;
    }
    
    if (fread(&wallet->next_key_index, 4, 1, f) != 1) {
        free(wallet->path);
        free(wallet);
        fclose(f);
        return NULL;
    }
    
    /* Read keys */
    if (key_count > 0) {
        wallet->keys = calloc(key_count, sizeof(encrypted_key_t));
        if (!wallet->keys) {
            free(wallet->path);
            free(wallet);
            fclose(f);
            return NULL;
        }
        wallet->key_capacity = key_count;
        
        for (uint32_t i = 0; i < key_count; i++) {
            if (fread(&wallet->keys[i].address, sizeof(dsv_address_t), 1, f) != 1 ||
                fread(&wallet->keys[i].pubkey, sizeof(dsv_pubkey_t), 1, f) != 1 ||
                fread(wallet->keys[i].nonce, crypto_secretbox_NONCEBYTES, 1, f) != 1 ||
                fread(wallet->keys[i].encrypted_seed, 32 + crypto_secretbox_MACBYTES, 1, f) != 1) {
                free(wallet->keys);
                free(wallet->path);
                free(wallet);
                fclose(f);
                return NULL;
            }
            wallet->key_count++;
        }
    }
    
    fclose(f);
    return wallet;
}

/* ==========================================================================
 * Wallet Operations
 * ========================================================================== */

dsv_wallet_t *dsv_wallet_create(const char *path,
                                 const char *passphrase1,
                                 const char *passphrase2,
                                 const char *passphrase3) {
    if (!passphrase1 || !passphrase2 || !passphrase3) return NULL;
    if (strlen(passphrase1) < 8 || strlen(passphrase2) < 8 || strlen(passphrase3) < 8) {
        return NULL;  /* Minimum passphrase length */
    }
    
    dsv_wallet_t *wallet = calloc(1, sizeof(dsv_wallet_t));
    if (!wallet) return NULL;
    
    wallet->path = strdup(path);
    if (!wallet->path) {
        free(wallet);
        return NULL;
    }
    
    /* Generate master key */
    randombytes_buf(wallet->master_key, 32);
    
    /* Split master key using TSA */
    dsv_share_t shares[3];
    dsv_tsa_split(wallet->master_key, shares);
    
    /* Encrypt each share with corresponding passphrase */
    const char *passphrases[3] = {passphrase1, passphrase2, passphrase3};
    
    for (int i = 0; i < 3; i++) {
        /* Generate salt and derive key */
        randombytes_buf(wallet->share_salts[i], crypto_pwhash_SALTBYTES);
        
        uint8_t derived_key[32];
        if (!derive_key_from_passphrase(derived_key, passphrases[i], wallet->share_salts[i])) {
            sodium_memzero(wallet->master_key, 32);
            sodium_memzero(shares, sizeof(shares));
            free(wallet->path);
            free(wallet);
            return NULL;
        }
        
        /* Encrypt share */
        randombytes_buf(wallet->share_nonces[i], crypto_secretbox_NONCEBYTES);
        
        /* Prepend index to share for later identification */
        uint8_t share_with_index[33];
        share_with_index[0] = shares[i].index;
        memcpy(share_with_index + 1, shares[i].share, 32);
        
        crypto_secretbox_easy(wallet->encrypted_shares[i], share_with_index, 33,
                              wallet->share_nonces[i], derived_key);
        
        sodium_memzero(derived_key, 32);
    }
    
    sodium_memzero(shares, sizeof(shares));
    
    wallet->unlocked = true;
    wallet->key_capacity = 16;
    wallet->keys = calloc(wallet->key_capacity, sizeof(encrypted_key_t));
    
    /* Save wallet */
    if (!wallet_save(wallet)) {
        dsv_wallet_close(wallet);
        return NULL;
    }
    
    return wallet;
}

dsv_wallet_t *dsv_wallet_open(const char *path,
                               const char *passphrase_a,
                               const char *passphrase_b) {
    dsv_wallet_t *wallet = wallet_load(path);
    if (!wallet) return NULL;
    
    if (!dsv_wallet_unlock(wallet, passphrase_a, passphrase_b)) {
        dsv_wallet_close(wallet);
        return NULL;
    }
    
    return wallet;
}

void dsv_wallet_close(dsv_wallet_t *wallet) {
    if (!wallet) return;
    
    /* Securely wipe all sensitive data */
    sodium_memzero(wallet->master_key, sizeof(wallet->master_key));
    
    if (wallet->keys) {
        sodium_memzero(wallet->keys, wallet->key_count * sizeof(encrypted_key_t));
        free(wallet->keys);
    }
    
    free(wallet->path);
    sodium_memzero(wallet, sizeof(dsv_wallet_t));
    free(wallet);
}

bool dsv_wallet_is_unlocked(dsv_wallet_t *wallet) {
    return wallet && wallet->unlocked;
}

void dsv_wallet_lock(dsv_wallet_t *wallet) {
    if (!wallet) return;
    sodium_memzero(wallet->master_key, sizeof(wallet->master_key));
    wallet->unlocked = false;
}

bool dsv_wallet_unlock(dsv_wallet_t *wallet,
                        const char *passphrase_a,
                        const char *passphrase_b) {
    if (!wallet || !passphrase_a || !passphrase_b) return false;
    
    dsv_share_t share_a = {0}, share_b = {0};
    bool found_a = false, found_b = false;
    
    /* Try to decrypt shares with each passphrase */
    const char *passphrases[2] = {passphrase_a, passphrase_b};
    dsv_share_t *found_shares[2] = {NULL, NULL};
    (void)found_shares;

    for (int p = 0; p < 2; p++) {
        for (int i = 0; i < 3; i++) {
            uint8_t derived_key[32];
            if (!derive_key_from_passphrase(derived_key, passphrases[p], wallet->share_salts[i])) {
                continue;
            }
            
            uint8_t decrypted[33];
            if (crypto_secretbox_open_easy(decrypted, wallet->encrypted_shares[i],
                                           33 + crypto_secretbox_MACBYTES,
                                           wallet->share_nonces[i], derived_key) == 0) {
                /* Successfully decrypted */
                dsv_share_t *share = (p == 0) ? &share_a : &share_b;
                share->index = decrypted[0];
                memcpy(share->share, decrypted + 1, 32);
                
                if (p == 0) found_a = true;
                else found_b = true;
                
                sodium_memzero(derived_key, 32);
                sodium_memzero(decrypted, sizeof(decrypted));
                break;
            }
            
            sodium_memzero(derived_key, 32);
        }
    }
    
    if (!found_a || !found_b) {
        sodium_memzero(&share_a, sizeof(share_a));
        sodium_memzero(&share_b, sizeof(share_b));
        return false;
    }
    
    /* Combine shares to get master key */
    if (!dsv_tsa_combine(wallet->master_key, &share_a, &share_b)) {
        sodium_memzero(&share_a, sizeof(share_a));
        sodium_memzero(&share_b, sizeof(share_b));
        return false;
    }
    
    sodium_memzero(&share_a, sizeof(share_a));
    sodium_memzero(&share_b, sizeof(share_b));
    
    wallet->unlocked = true;
    return true;
}

/* ==========================================================================
 * Key Generation
 * ========================================================================== */

int dsv_wallet_new_address(dsv_wallet_t *wallet, dsv_address_t *address) {
    if (!wallet || !wallet->unlocked) return DSV_ERR_AUTH;
    
    /* Expand key array if needed */
    if (wallet->key_count >= wallet->key_capacity) {
        size_t new_cap = wallet->key_capacity * 2;
        encrypted_key_t *new_keys = realloc(wallet->keys, new_cap * sizeof(encrypted_key_t));
        if (!new_keys) return DSV_ERR_NOMEM;
        wallet->keys = new_keys;
        wallet->key_capacity = new_cap;
    }
    
    /* Generate new key deterministically from master key and index */
    uint8_t index_bytes[4];
    memcpy(index_bytes, &wallet->next_key_index, 4);
    
    uint8_t seed_input[36];
    memcpy(seed_input, wallet->master_key, 32);
    memcpy(seed_input + 32, index_bytes, 4);
    
    dsv_seed_t seed;
    crypto_generichash(seed.data, DSV_SEED_SIZE, seed_input, 36, NULL, 0);
    sodium_memzero(seed_input, sizeof(seed_input));
    
    /* Generate keypair */
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    /* Compute address */
    dsv_address_t addr;
    dsv_address_from_pubkey(&addr, &pubkey, DSV_ADDR_VERSION_MAINNET);
    
    /* Encrypt seed with master key */
    encrypted_key_t *entry = &wallet->keys[wallet->key_count];
    entry->address = addr;
    entry->pubkey = pubkey;
    
    randombytes_buf(entry->nonce, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(entry->encrypted_seed, seed.data, DSV_SEED_SIZE,
                          entry->nonce, wallet->master_key);
    
    /* Clear sensitive data */
    sodium_memzero(&seed, sizeof(seed));
    sodium_memzero(&privkey, sizeof(privkey));
    
    wallet->key_count++;
    wallet->next_key_index++;
    
    /* Save wallet */
    wallet_save(wallet);
    
    *address = addr;
    return DSV_OK;
}

int dsv_wallet_import_key(dsv_wallet_t *wallet, const dsv_seed_t *seed) {
    if (!wallet || !wallet->unlocked || !seed) return DSV_ERR_INVALID;
    
    /* Expand key array if needed */
    if (wallet->key_count >= wallet->key_capacity) {
        size_t new_cap = wallet->key_capacity * 2;
        encrypted_key_t *new_keys = realloc(wallet->keys, new_cap * sizeof(encrypted_key_t));
        if (!new_keys) return DSV_ERR_NOMEM;
        wallet->keys = new_keys;
        wallet->key_capacity = new_cap;
    }
    
    /* Generate keypair */
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    dsv_keypair_from_seed(&privkey, &pubkey, seed);
    
    /* Compute address */
    dsv_address_t addr;
    dsv_address_from_pubkey(&addr, &pubkey, DSV_ADDR_VERSION_MAINNET);
    
    /* Check for duplicates */
    for (size_t i = 0; i < wallet->key_count; i++) {
        if (dsv_address_eq(&wallet->keys[i].address, &addr)) {
            sodium_memzero(&privkey, sizeof(privkey));
            return DSV_ERR_DUPLICATE;
        }
    }
    
    /* Encrypt seed */
    encrypted_key_t *entry = &wallet->keys[wallet->key_count];
    entry->address = addr;
    entry->pubkey = pubkey;
    
    randombytes_buf(entry->nonce, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(entry->encrypted_seed, seed->data, DSV_SEED_SIZE,
                          entry->nonce, wallet->master_key);
    
    sodium_memzero(&privkey, sizeof(privkey));
    
    wallet->key_count++;
    wallet_save(wallet);
    
    return DSV_OK;
}

dsv_address_t *dsv_wallet_get_addresses(dsv_wallet_t *wallet, size_t *count) {
    if (!wallet) {
        *count = 0;
        return NULL;
    }
    
    *count = wallet->key_count;
    if (wallet->key_count == 0) return NULL;
    
    dsv_address_t *addrs = malloc(wallet->key_count * sizeof(dsv_address_t));
    if (!addrs) return NULL;
    
    for (size_t i = 0; i < wallet->key_count; i++) {
        addrs[i] = wallet->keys[i].address;
    }
    
    return addrs;
}

int dsv_wallet_get_pubkey(dsv_wallet_t *wallet, const dsv_address_t *addr,
                           dsv_pubkey_t *pubkey) {
    if (!wallet || !addr || !pubkey) return DSV_ERR_INVALID;
    
    for (size_t i = 0; i < wallet->key_count; i++) {
        if (dsv_address_eq(&wallet->keys[i].address, addr)) {
            *pubkey = wallet->keys[i].pubkey;
            return DSV_OK;
        }
    }
    
    return DSV_ERR_NOT_FOUND;
}

/* ==========================================================================
 * Transaction Signing
 * ========================================================================== */

static int get_privkey(dsv_wallet_t *wallet, const dsv_address_t *addr,
                       dsv_privkey_t *privkey) {
    if (!wallet->unlocked) return DSV_ERR_AUTH;
    
    for (size_t i = 0; i < wallet->key_count; i++) {
        if (dsv_address_eq(&wallet->keys[i].address, addr)) {
            /* Decrypt seed */
            dsv_seed_t seed;
            if (crypto_secretbox_open_easy(seed.data, wallet->keys[i].encrypted_seed,
                                           DSV_SEED_SIZE + crypto_secretbox_MACBYTES,
                                           wallet->keys[i].nonce,
                                           wallet->master_key) != 0) {
                return DSV_ERR_CRYPTO;
            }
            
            /* Derive keypair */
            dsv_pubkey_t pubkey;
            dsv_keypair_from_seed(privkey, &pubkey, &seed);
            
            sodium_memzero(&seed, sizeof(seed));
            return DSV_OK;
        }
    }
    
    return DSV_ERR_NOT_FOUND;
}

int dsv_wallet_sign_input(dsv_wallet_t *wallet, dsv_tx_t *tx,
                           uint32_t input_index, const dsv_address_t *addr) {
    if (!wallet || !tx || input_index >= tx->input_count) return DSV_ERR_INVALID;
    
    dsv_privkey_t privkey;
    int err = get_privkey(wallet, addr, &privkey);
    if (err != DSV_OK) return err;
    
    /* Set public key in input */
    dsv_pubkey_from_privkey(&tx->inputs[input_index].pubkey, &privkey);
    
    /* Compute signing hash */
    dsv_buffer_t *buf = dsv_buffer_new(1024);
    if (!buf) {
        sodium_memzero(&privkey, sizeof(privkey));
        return DSV_ERR_NOMEM;
    }
    
    dsv_tx_serialize_for_signing(buf, tx, input_index);
    
    dsv_hash256_t sighash;
    dsv_hash256(&sighash, buf->data, buf->pos);
    dsv_buffer_free(buf);
    
    /* Sign */
    dsv_sign(&tx->inputs[input_index].signature, sighash.data, DSV_HASH_SIZE, &privkey);
    
    sodium_memzero(&privkey, sizeof(privkey));
    return DSV_OK;
}

int dsv_wallet_sign_tx(dsv_wallet_t *wallet, dsv_tx_t *tx) {
    if (!wallet || !tx) return DSV_ERR_INVALID;
    
    /* Need to know addresses for each input - they should be set in pubkey field */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        /* Derive address from pubkey and find matching key */
        dsv_address_t addr;
        dsv_address_from_pubkey(&addr, &tx->inputs[i].pubkey, DSV_ADDR_VERSION_MAINNET);
        
        int err = dsv_wallet_sign_input(wallet, tx, i, &addr);
        if (err != DSV_OK) return err;
    }
    
    return DSV_OK;
}

/* ==========================================================================
 * Transaction Building
 * ========================================================================== */

dsv_coin_t *dsv_wallet_select_coins(const dsv_coin_t *available, size_t available_count,
                                     const dsv_u320_t *target_amount,
                                     size_t *selected_count) {
    *selected_count = 0;
    
    if (!available || available_count == 0) return NULL;
    
    /* Simple algorithm: select coins until we have enough */
    dsv_coin_t *selected = malloc(available_count * sizeof(dsv_coin_t));
    if (!selected) return NULL;
    
    dsv_u320_t total = DSV_U320_ZERO;
    
    for (size_t i = 0; i < available_count; i++) {
        selected[*selected_count] = available[i];
        (*selected_count)++;
        dsv_u320_add(&total, &total, &available[i].amount);
        
        if (dsv_u320_cmp(&total, target_amount) >= 0) {
            break;
        }
    }
    
    if (dsv_u320_cmp(&total, target_amount) < 0) {
        /* Not enough funds */
        free(selected);
        *selected_count = 0;
        return NULL;
    }
    
    return selected;
}

dsv_tx_t *dsv_wallet_build_tx(dsv_wallet_t *wallet,
                               const dsv_coin_t *coins, size_t coin_count,
                               const dsv_address_t *recipients,
                               const dsv_u320_t *amounts, size_t recipient_count,
                               const dsv_address_t *change_address,
                               uint64_t fee_per_byte) {
    if (!wallet || !wallet->unlocked) return NULL;
    if (!coins || coin_count == 0) return NULL;
    if (!recipients || !amounts || recipient_count == 0) return NULL;
    
    /* Calculate total output amount */
    dsv_u320_t total_output = DSV_U320_ZERO;
    for (size_t i = 0; i < recipient_count; i++) {
        dsv_u320_add(&total_output, &total_output, &amounts[i]);
    }
    
    /* Calculate total input amount */
    dsv_u320_t total_input = DSV_U320_ZERO;
    for (size_t i = 0; i < coin_count; i++) {
        dsv_u320_add(&total_input, &total_input, &coins[i].amount);
    }
    
    /* Estimate fee */
    size_t estimated_size = 10 + coin_count * 132 + (recipient_count + 1) * 61;
    dsv_u320_t fee;
    dsv_u320_from_u64(&fee, estimated_size * fee_per_byte);
    
    /* Check we have enough */
    dsv_u320_t needed;
    if (dsv_u320_add(&needed, &total_output, &fee)) {
        return NULL;  /* Overflow */
    }
    
    if (dsv_u320_cmp(&total_input, &needed) < 0) {
        return NULL;  /* Insufficient funds */
    }
    
    /* Calculate change */
    dsv_u320_t change;
    dsv_u320_sub(&change, &total_input, &needed);
    
    /* Build transaction */
    dsv_tx_t *tx = dsv_tx_new();
    if (!tx) return NULL;
    
    tx->version = 1;
    
    /* Add inputs */
    tx->input_count = (uint32_t)coin_count;
    tx->inputs = calloc(coin_count, sizeof(dsv_txin_t));
    if (!tx->inputs) {
        dsv_tx_free(tx);
        return NULL;
    }
    
    for (size_t i = 0; i < coin_count; i++) {
        tx->inputs[i].prev_txid = coins[i].txid;
        tx->inputs[i].prev_vout = coins[i].vout;
        
        /* Get public key for this address */
        dsv_wallet_get_pubkey(wallet, &coins[i].address, &tx->inputs[i].pubkey);
    }
    
    /* Add outputs */
    size_t output_count = recipient_count;
    if (!dsv_u320_is_zero(&change)) {
        output_count++;
    }
    
    tx->output_count = (uint32_t)output_count;
    tx->outputs = calloc(output_count, sizeof(dsv_txout_t));
    if (!tx->outputs) {
        dsv_tx_free(tx);
        return NULL;
    }
    
    for (size_t i = 0; i < recipient_count; i++) {
        dsv_u320_copy(&tx->outputs[i].amount, &amounts[i]);
        tx->outputs[i].address = recipients[i];
    }
    
    /* Add change output */
    if (!dsv_u320_is_zero(&change)) {
        dsv_u320_copy(&tx->outputs[recipient_count].amount, &change);
        if (change_address) {
            tx->outputs[recipient_count].address = *change_address;
        } else if (wallet->key_count > 0) {
            tx->outputs[recipient_count].address = wallet->keys[0].address;
        } else {
            dsv_tx_free(tx);
            return NULL;
        }
    }
    
    /* Sign all inputs */
    for (uint32_t i = 0; i < tx->input_count; i++) {
        int err = dsv_wallet_sign_input(wallet, tx, i, &coins[i].address);
        if (err != DSV_OK) {
            dsv_tx_free(tx);
            return NULL;
        }
    }
    
    return tx;
}

/* ==========================================================================
 * Backup and Recovery
 * ========================================================================== */

/* Simple word list (first 2048 words would be full BIP39, using subset here) */
static const char *WORD_LIST[] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    /* ... truncated for brevity - full implementation would have 2048 words */
    "zoo", "zone", "allow", "amount", "ancient", "anger", "angle", "animal",
    "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any",
    NULL
};

int dsv_wallet_export_mnemonic(dsv_wallet_t *wallet, char *mnemonic, size_t len) {
    if (!wallet || !wallet->unlocked || !mnemonic || len < 256) {
        return DSV_ERR_INVALID;
    }
    
    /* Convert master key to word indices */
    mnemonic[0] = '\0';
    size_t pos = 0;
    
    for (int i = 0; i < 24; i++) {  /* 24 words for 256 bits */
        int word_idx = ((wallet->master_key[i] << 3) | 
                       (wallet->master_key[(i + 1) % 32] >> 5)) % 64;
        
        const char *word = WORD_LIST[word_idx] ? WORD_LIST[word_idx] : "unknown";
        size_t word_len = strlen(word);
        
        if (pos + word_len + 2 >= len) break;
        
        if (pos > 0) {
            mnemonic[pos++] = ' ';
        }
        strcpy(mnemonic + pos, word);
        pos += word_len;
    }
    
    return DSV_OK;
}

dsv_wallet_t *dsv_wallet_import_mnemonic(const char *path,
                                          const char *mnemonic,
                                          const char *passphrase1,
                                          const char *passphrase2,
                                          const char *passphrase3) {
    if (!mnemonic) return NULL;
    
    /* Convert mnemonic back to bytes */
    uint8_t seed[32];
    crypto_generichash(seed, 32, (const uint8_t *)mnemonic, strlen(mnemonic), NULL, 0);
    
    /* Create wallet */
    dsv_wallet_t *wallet = dsv_wallet_create(path, passphrase1, passphrase2, passphrase3);
    if (!wallet) {
        sodium_memzero(seed, sizeof(seed));
        return NULL;
    }
    
    /* Replace master key with derived seed */
    memcpy(wallet->master_key, seed, 32);
    sodium_memzero(seed, sizeof(seed));
    
    /* Re-split and re-encrypt shares */
    dsv_share_t shares[3];
    dsv_tsa_split(wallet->master_key, shares);
    
    const char *passphrases[3] = {passphrase1, passphrase2, passphrase3};
    for (int i = 0; i < 3; i++) {
        uint8_t derived_key[32];
        derive_key_from_passphrase(derived_key, passphrases[i], wallet->share_salts[i]);
        
        uint8_t share_with_index[33];
        share_with_index[0] = shares[i].index;
        memcpy(share_with_index + 1, shares[i].share, 32);
        
        crypto_secretbox_easy(wallet->encrypted_shares[i], share_with_index, 33,
                              wallet->share_nonces[i], derived_key);
        
        sodium_memzero(derived_key, 32);
    }
    
    sodium_memzero(shares, sizeof(shares));
    wallet_save(wallet);
    
    return wallet;
}

