/**
 * DSV Wallet Integration Tests
 * 
 * Tests for wallet operations including:
 * - Key generation with TSA
 * - Address creation
 * - Transaction signing
 * - Backup and restore
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "dsv_wallet.h"
#include "dsv_crypto.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  Testing %s... ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
    return; \
} while(0)

/* Test directory */
static const char *TEST_DIR = "./test_wallet_data";

/* Helper: Clean up test directory */
static void cleanup_test_dir(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DIR);
    system(cmd);
}

/* ============================================================
 * Test: Wallet creation
 * ============================================================ */
static void test_wallet_creation(void) {
    TEST("wallet creation");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {
        "correct horse battery staple",
        "abandon abandon abandon abandon",
        "zoo zoo zoo zoo zoo zoo"
    };
    
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    
    dsv_wallet_close(&wallet);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: TSA unlock with 2 of 3 passphrases
 * ============================================================ */
static void test_tsa_unlock(void) {
    TEST("TSA 2-of-3 unlock");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {
        "passphrase one secret",
        "passphrase two hidden",
        "passphrase three covert"
    };
    
    /* Create wallet */
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    dsv_wallet_close(&wallet);
    
    /* Test: Unlock with passphrases 0 and 1 */
    const char *unlock_01[] = {passphrases[0], passphrases[1]};
    err = dsv_wallet_open(&wallet, TEST_DIR, unlock_01, 2, (int[]){0, 1});
    if (err != DSV_WALLET_OK) {
        FAIL("unlock with shares 0,1 failed");
    }
    dsv_wallet_close(&wallet);
    
    /* Test: Unlock with passphrases 0 and 2 */
    const char *unlock_02[] = {passphrases[0], passphrases[2]};
    err = dsv_wallet_open(&wallet, TEST_DIR, unlock_02, 2, (int[]){0, 2});
    if (err != DSV_WALLET_OK) {
        FAIL("unlock with shares 0,2 failed");
    }
    dsv_wallet_close(&wallet);
    
    /* Test: Unlock with passphrases 1 and 2 */
    const char *unlock_12[] = {passphrases[1], passphrases[2]};
    err = dsv_wallet_open(&wallet, TEST_DIR, unlock_12, 2, (int[]){1, 2});
    if (err != DSV_WALLET_OK) {
        FAIL("unlock with shares 1,2 failed");
    }
    dsv_wallet_close(&wallet);
    
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: TSA unlock with single passphrase fails
 * ============================================================ */
static void test_tsa_single_fails(void) {
    TEST("TSA single passphrase fails");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {
        "alpha beta gamma",
        "delta epsilon zeta",
        "eta theta iota"
    };
    
    /* Create wallet */
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    dsv_wallet_close(&wallet);
    
    /* Try to unlock with only 1 passphrase - should fail */
    const char *unlock_single[] = {passphrases[0]};
    err = dsv_wallet_open(&wallet, TEST_DIR, unlock_single, 1, (int[]){0});
    
    if (err == DSV_WALLET_OK) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("single passphrase should not unlock wallet");
    }
    
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Wrong passphrase fails
 * ============================================================ */
static void test_wrong_passphrase(void) {
    TEST("wrong passphrase fails");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {
        "correct pass one",
        "correct pass two",
        "correct pass three"
    };
    
    /* Create wallet */
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    dsv_wallet_close(&wallet);
    
    /* Try to unlock with wrong passphrases */
    const char *wrong[] = {"wrong pass one", "wrong pass two"};
    err = dsv_wallet_open(&wallet, TEST_DIR, wrong, 2, (int[]){0, 1});
    
    if (err == DSV_WALLET_OK) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("wrong passphrases should not unlock wallet");
    }
    
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Address generation
 * ============================================================ */
static void test_address_generation(void) {
    TEST("address generation");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {"pass1", "pass2", "pass3"};
    
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    
    /* Generate new address */
    char address[64];
    err = dsv_wallet_new_address(&wallet, address, sizeof(address));
    if (err != DSV_WALLET_OK) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("address generation failed");
    }
    
    /* Address should start with '1' (mainnet) */
    if (address[0] != '1') {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("address should start with '1'");
    }
    
    /* Address should be valid length (25-34 chars for Base58Check) */
    size_t addr_len = strlen(address);
    if (addr_len < 25 || addr_len > 34) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("address length invalid");
    }
    
    /* Generate another address - should be different */
    char address2[64];
    err = dsv_wallet_new_address(&wallet, address2, sizeof(address2));
    if (err != DSV_WALLET_OK) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("second address generation failed");
    }
    
    if (strcmp(address, address2) == 0) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("addresses should be different");
    }
    
    dsv_wallet_close(&wallet);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Transaction signing
 * ============================================================ */
static void test_tx_signing(void) {
    TEST("transaction signing");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {"sign1", "sign2", "sign3"};
    
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    
    /* Create a mock transaction */
    dsv_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.input_count = 1;
    tx.output_count = 1;
    
    tx.inputs = calloc(1, sizeof(dsv_tx_input_t));
    tx.outputs = calloc(1, sizeof(dsv_tx_output_t));
    
    /* Fill with test data */
    for (int i = 0; i < 32; i++) {
        tx.inputs[0].prev_txid.data[i] = i;
    }
    tx.inputs[0].prev_vout = 0;
    
    dsv_u320_from_u64(&tx.outputs[0].amount, 1000);
    
    /* Sign the transaction */
    err = dsv_wallet_sign_tx(&wallet, &tx, 0);
    if (err != DSV_WALLET_OK) {
        free(tx.inputs);
        free(tx.outputs);
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("signing failed");
    }
    
    /* Verify signature is present */
    if (tx.inputs[0].sig_len == 0) {
        free(tx.inputs);
        free(tx.outputs);
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("no signature produced");
    }
    
    /* Verify pubkey is present */
    if (tx.inputs[0].pubkey_len == 0) {
        free(tx.inputs);
        free(tx.outputs);
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("no pubkey produced");
    }
    
    free(tx.inputs);
    free(tx.outputs);
    dsv_wallet_close(&wallet);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Balance tracking
 * ============================================================ */
static void test_balance(void) {
    TEST("balance tracking");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {"bal1", "bal2", "bal3"};
    
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    
    /* New wallet should have zero balance */
    dsv_u320_t balance;
    err = dsv_wallet_get_balance(&wallet, &balance);
    if (err != DSV_WALLET_OK) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("get balance failed");
    }
    
    if (!dsv_u320_is_zero(&balance)) {
        dsv_wallet_close(&wallet);
        cleanup_test_dir();
        FAIL("new wallet should have zero balance");
    }
    
    dsv_wallet_close(&wallet);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Wallet backup and restore
 * ============================================================ */
static void test_backup_restore(void) {
    TEST("backup and restore");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {"backup1", "backup2", "backup3"};
    char original_address[64];
    
    /* Create wallet and generate address */
    {
        dsv_wallet_t wallet;
        dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
        if (err != DSV_WALLET_OK) {
            FAIL("wallet creation failed");
        }
        
        err = dsv_wallet_new_address(&wallet, original_address, sizeof(original_address));
        if (err != DSV_WALLET_OK) {
            dsv_wallet_close(&wallet);
            cleanup_test_dir();
            FAIL("address generation failed");
        }
        
        dsv_wallet_close(&wallet);
    }
    
    /* Reopen wallet and verify address is accessible */
    {
        dsv_wallet_t wallet;
        const char *unlock[] = {passphrases[0], passphrases[2]};
        dsv_wallet_error_t err = dsv_wallet_open(&wallet, TEST_DIR, unlock, 2, (int[]){0, 2});
        if (err != DSV_WALLET_OK) {
            cleanup_test_dir();
            FAIL("wallet reopen failed");
        }
        
        /* Get all addresses */
        char **addresses;
        size_t count;
        err = dsv_wallet_list_addresses(&wallet, &addresses, &count);
        if (err != DSV_WALLET_OK) {
            dsv_wallet_close(&wallet);
            cleanup_test_dir();
            FAIL("list addresses failed");
        }
        
        /* Find original address */
        bool found = false;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(addresses[i], original_address) == 0) {
                found = true;
            }
            free(addresses[i]);
        }
        free(addresses);
        
        if (!found) {
            dsv_wallet_close(&wallet);
            cleanup_test_dir();
            FAIL("original address not found after reopen");
        }
        
        dsv_wallet_close(&wallet);
    }
    
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Memory zeroing after close
 * ============================================================ */
static void test_memory_zeroing(void) {
    TEST("memory zeroing after close");
    
    cleanup_test_dir();
    
    const char *passphrases[] = {"zero1", "zero2", "zero3"};
    
    dsv_wallet_t wallet;
    dsv_wallet_error_t err = dsv_wallet_create(&wallet, TEST_DIR, passphrases, 3);
    if (err != DSV_WALLET_OK) {
        FAIL("wallet creation failed");
    }
    
    /* Store a copy of where sensitive data might be */
    /* (This is a simplified test - real test would check actual memory) */
    
    dsv_wallet_close(&wallet);
    
    /* After close, wallet struct should be zeroed */
    /* Check that the wallet appears empty */
    bool all_zero = true;
    uint8_t *bytes = (uint8_t *)&wallet;
    for (size_t i = 0; i < sizeof(wallet); i++) {
        if (bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (!all_zero) {
        cleanup_test_dir();
        FAIL("wallet memory not zeroed after close");
    }
    
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Coin selection
 * ============================================================ */
static void test_coin_selection(void) {
    TEST("coin selection");
    
    /* Create mock UTXOs */
    dsv_utxo_t utxos[3];
    
    dsv_u320_from_u64(&utxos[0].amount, 100000);
    dsv_u320_from_u64(&utxos[1].amount, 50000);
    dsv_u320_from_u64(&utxos[2].amount, 75000);
    
    /* Select coins for 120000 (should select 100000 + 50000) */
    dsv_u320_t target;
    dsv_u320_from_u64(&target, 120000);
    
    size_t selected_indices[3];
    size_t selected_count;
    dsv_u320_t total_selected;
    
    bool result = dsv_select_coins(utxos, 3, &target, 
                                   selected_indices, &selected_count, 
                                   &total_selected);
    
    if (!result) {
        FAIL("coin selection failed");
    }
    
    if (selected_count < 2) {
        FAIL("should select at least 2 UTXOs");
    }
    
    /* Verify total >= target */
    if (dsv_u320_cmp(&total_selected, &target) < 0) {
        FAIL("selected total less than target");
    }
    
    PASS();
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void) {
    if (!dsv_crypto_init()) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    
    printf("DSV Wallet Integration Tests\n");
    printf("============================\n\n");
    
    test_wallet_creation();
    test_tsa_unlock();
    test_tsa_single_fails();
    test_wrong_passphrase();
    test_address_generation();
    test_tx_signing();
    test_balance();
    test_backup_restore();
    test_memory_zeroing();
    test_coin_selection();
    
    /* Summary */
    printf("\n============================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    /* Final cleanup */
    cleanup_test_dir();
    
    return (tests_passed == tests_run) ? 0 : 1;
}

