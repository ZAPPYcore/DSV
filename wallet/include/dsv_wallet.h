/**
 * DSV Secure Wallet
 * 
 * Features:
 * - TSA (Threshold Secret Sharing) key protection (2-of-3 passphrases)
 * - No plaintext key storage
 * - Ed25519 signing
 * - Simple deterministic coin selection
 */

#ifndef DSV_WALLET_H
#define DSV_WALLET_H

#include "dsv_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsv_wallet_s dsv_wallet_t;

/* ==========================================================================
 * TSA (Threshold Secret Sharing)
 * 
 * Uses Shamir's Secret Sharing scheme to split the wallet encryption key
 * into 3 shares. Any 2 shares can reconstruct the key.
 * ========================================================================== */

typedef struct {
    uint8_t share[32];
    uint8_t index;  /* 1, 2, or 3 */
} dsv_share_t;

/**
 * Split a secret into 3 shares (2-of-3 scheme).
 */
void dsv_tsa_split(const uint8_t secret[32], dsv_share_t shares[3]);

/**
 * Reconstruct secret from any 2 shares.
 * Returns true on success, false if shares are invalid.
 */
bool dsv_tsa_combine(uint8_t secret[32], const dsv_share_t *share1,
                     const dsv_share_t *share2);

/* ==========================================================================
 * Wallet Key Management
 * ========================================================================== */

typedef struct {
    dsv_address_t address;
    dsv_pubkey_t pubkey;
    /* Private key is encrypted, never stored in plain */
} dsv_wallet_key_t;

/* ==========================================================================
 * Wallet Operations
 * ========================================================================== */

/**
 * Create a new wallet with TSA protection.
 * Generates 3 passphrases that the user must save.
 * Any 2 of 3 are needed to unlock the wallet.
 */
dsv_wallet_t *dsv_wallet_create(const char *path,
                                 const char *passphrase1,
                                 const char *passphrase2,
                                 const char *passphrase3);

/**
 * Open existing wallet with 2 of 3 passphrases.
 */
dsv_wallet_t *dsv_wallet_open(const char *path,
                               const char *passphrase_a,
                               const char *passphrase_b);

/**
 * Close wallet and securely wipe memory.
 */
void dsv_wallet_close(dsv_wallet_t *wallet);

/**
 * Check if wallet is unlocked.
 */
bool dsv_wallet_is_unlocked(dsv_wallet_t *wallet);

/**
 * Lock wallet (clear decrypted keys from memory).
 */
void dsv_wallet_lock(dsv_wallet_t *wallet);

/**
 * Unlock wallet with 2 of 3 passphrases.
 */
bool dsv_wallet_unlock(dsv_wallet_t *wallet,
                        const char *passphrase_a,
                        const char *passphrase_b);

/* ==========================================================================
 * Key Generation
 * ========================================================================== */

/**
 * Generate a new key pair in the wallet.
 * Returns the address of the new key.
 */
int dsv_wallet_new_address(dsv_wallet_t *wallet, dsv_address_t *address);

/**
 * Import an existing seed/private key.
 */
int dsv_wallet_import_key(dsv_wallet_t *wallet, const dsv_seed_t *seed);

/**
 * Get all addresses in wallet.
 */
dsv_address_t *dsv_wallet_get_addresses(dsv_wallet_t *wallet, size_t *count);

/**
 * Get public key for address.
 */
int dsv_wallet_get_pubkey(dsv_wallet_t *wallet, const dsv_address_t *addr,
                           dsv_pubkey_t *pubkey);

/* ==========================================================================
 * Transaction Signing
 * ========================================================================== */

/**
 * Sign a transaction.
 * Wallet must be unlocked.
 */
int dsv_wallet_sign_tx(dsv_wallet_t *wallet, dsv_tx_t *tx);

/**
 * Sign a single input of a transaction.
 */
int dsv_wallet_sign_input(dsv_wallet_t *wallet, dsv_tx_t *tx,
                           uint32_t input_index, const dsv_address_t *addr);

/* ==========================================================================
 * Transaction Building
 * ========================================================================== */

typedef struct {
    dsv_hash256_t txid;
    uint32_t vout;
    dsv_u320_t amount;
    dsv_address_t address;
} dsv_coin_t;

/**
 * Build a transaction.
 * 
 * @param wallet Wallet for signing
 * @param coins Available coins (UTXOs)
 * @param coin_count Number of available coins
 * @param recipients Recipient addresses
 * @param amounts Amounts for each recipient
 * @param recipient_count Number of recipients
 * @param change_address Address for change (if NULL, uses first wallet address)
 * @param fee_per_byte Fee rate in LGB per byte
 * @return Signed transaction or NULL on failure
 */
dsv_tx_t *dsv_wallet_build_tx(dsv_wallet_t *wallet,
                               const dsv_coin_t *coins, size_t coin_count,
                               const dsv_address_t *recipients,
                               const dsv_u320_t *amounts, size_t recipient_count,
                               const dsv_address_t *change_address,
                               uint64_t fee_per_byte);

/**
 * Select coins for transaction using simple deterministic algorithm.
 * Selects oldest coins first to maximize coin age.
 */
dsv_coin_t *dsv_wallet_select_coins(const dsv_coin_t *available, size_t available_count,
                                     const dsv_u320_t *target_amount,
                                     size_t *selected_count);

/* ==========================================================================
 * Backup and Recovery
 * ========================================================================== */

/**
 * Export wallet seed words (BIP39-like mnemonic).
 * Wallet must be unlocked.
 */
int dsv_wallet_export_mnemonic(dsv_wallet_t *wallet, char *mnemonic, size_t len);

/**
 * Import wallet from mnemonic seed words.
 */
dsv_wallet_t *dsv_wallet_import_mnemonic(const char *path,
                                          const char *mnemonic,
                                          const char *passphrase1,
                                          const char *passphrase2,
                                          const char *passphrase3);

#ifdef __cplusplus
}
#endif

#endif /* DSV_WALLET_H */

