/**
 * DSV Chain Integration Tests
 * 
 * Tests for full blockchain operations including:
 * - Genesis block creation
 * - Mining
 * - Spending
 * - Reorg handling
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "dsv_chain.h"
#include "dsv_storage.h"
#include "dsv_mempool.h"
#include "dsv_crypto.h"
#include "dsv_consensus.h"

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
static const char *TEST_DIR = "./test_chain_data";

/* Helper: Clean up test directory */
static void cleanup_test_dir(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DIR);
    system(cmd);
}

/* ============================================================
 * Test: Genesis block creation
 * ============================================================ */
static void test_genesis_creation(void) {
    TEST("genesis block creation");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    /* Get genesis block */
    dsv_block_t *genesis = dsv_chain_get_block(&chain, 0);
    if (!genesis) {
        dsv_chain_destroy(&chain);
        FAIL("no genesis block");
    }
    
    /* Verify genesis block properties */
    if (genesis->header.time == 0) {
        dsv_block_free(genesis);
        dsv_chain_destroy(&chain);
        FAIL("genesis time is zero");
    }
    
    /* Genesis prev_hash should be all zeros */
    dsv_hash256_t zero_hash;
    memset(&zero_hash, 0, sizeof(zero_hash));
    
    if (memcmp(genesis->header.prev_hash.data, zero_hash.data, 32) != 0) {
        dsv_block_free(genesis);
        dsv_chain_destroy(&chain);
        FAIL("genesis prev_hash not zero");
    }
    
    dsv_block_free(genesis);
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Mining a block
 * ============================================================ */
static void test_mining(void) {
    TEST("mining a block");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    /* Generate a keypair for mining rewards */
    dsv_keypair_t miner_key;
    dsv_keygen(&miner_key);
    
    /* Mine a block */
    dsv_block_t *block = dsv_mine_block(&chain, &miner_key.pubkey, 1000);
    if (!block) {
        dsv_chain_destroy(&chain);
        FAIL("mining failed");
    }
    
    /* Add block to chain */
    if (!dsv_chain_add_block(&chain, block)) {
        dsv_block_free(block);
        dsv_chain_destroy(&chain);
        FAIL("failed to add mined block");
    }
    
    /* Verify chain height increased */
    if (dsv_chain_height(&chain) != 1) {
        dsv_block_free(block);
        dsv_chain_destroy(&chain);
        FAIL("chain height should be 1");
    }
    
    dsv_block_free(block);
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Mining multiple blocks
 * ============================================================ */
static void test_mining_multiple(void) {
    TEST("mining multiple blocks");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    dsv_keypair_t miner_key;
    dsv_keygen(&miner_key);
    
    /* Mine 5 blocks */
    for (int i = 0; i < 5; i++) {
        dsv_block_t *block = dsv_mine_block(&chain, &miner_key.pubkey, 100);
        if (!block) {
            dsv_chain_destroy(&chain);
            FAIL("mining failed");
        }
        
        if (!dsv_chain_add_block(&chain, block)) {
            dsv_block_free(block);
            dsv_chain_destroy(&chain);
            FAIL("failed to add block");
        }
        
        dsv_block_free(block);
    }
    
    if (dsv_chain_height(&chain) != 5) {
        dsv_chain_destroy(&chain);
        FAIL("chain height should be 5");
    }
    
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Transaction creation and spending
 * ============================================================ */
static void test_spending(void) {
    TEST("transaction spending");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    /* Generate keys for Alice and Bob */
    dsv_keypair_t alice_key, bob_key;
    dsv_keygen(&alice_key);
    dsv_keygen(&bob_key);
    
    /* Mine 101 blocks to Alice (100 for maturity + 1 to spend) */
    for (int i = 0; i < 101; i++) {
        dsv_block_t *block = dsv_mine_block(&chain, &alice_key.pubkey, 10);
        if (!block || !dsv_chain_add_block(&chain, block)) {
            if (block) dsv_block_free(block);
            dsv_chain_destroy(&chain);
            FAIL("mining failed");
        }
        dsv_block_free(block);
    }
    
    /* Alice's first block reward should now be mature */
    dsv_utxo_set_t *utxos = dsv_chain_get_utxos_for_pubkey(&chain, &alice_key.pubkey);
    if (!utxos || utxos->count == 0) {
        dsv_utxo_set_free(utxos);
        dsv_chain_destroy(&chain);
        FAIL("Alice should have UTXOs");
    }
    
    /* Create transaction: Alice sends to Bob */
    dsv_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.input_count = 1;
    tx.output_count = 2;  /* Bob's payment + Alice's change */
    
    tx.inputs = calloc(1, sizeof(dsv_tx_input_t));
    tx.outputs = calloc(2, sizeof(dsv_tx_output_t));
    
    /* Use first mature UTXO */
    memcpy(tx.inputs[0].prev_txid.data, utxos->utxos[0].txid.data, 32);
    tx.inputs[0].prev_vout = utxos->utxos[0].vout;
    
    /* Bob gets half */
    dsv_u320_t half_amount;
    dsv_u320_from_u64(&half_amount, utxos->utxos[0].amount.parts[0] / 2);
    tx.outputs[0].amount = half_amount;
    dsv_hash160(tx.outputs[0].pubkey_hash, bob_key.pubkey.data, 32);
    
    /* Alice gets change (minus fee) */
    dsv_u320_t change;
    dsv_u320_sub(&change, &utxos->utxos[0].amount, &half_amount);
    dsv_u320_t fee;
    dsv_u320_from_u64(&fee, 1000);  /* Small fee */
    dsv_u320_sub(&tx.outputs[1].amount, &change, &fee);
    dsv_hash160(tx.outputs[1].pubkey_hash, alice_key.pubkey.data, 32);
    
    /* Sign the transaction */
    if (!dsv_sign_tx(&tx, 0, &alice_key.privkey)) {
        free(tx.inputs);
        free(tx.outputs);
        dsv_utxo_set_free(utxos);
        dsv_chain_destroy(&chain);
        FAIL("signing failed");
    }
    
    /* Add to mempool */
    dsv_mempool_t mempool;
    dsv_mempool_init(&mempool);
    
    if (!dsv_mempool_add(&mempool, &tx)) {
        free(tx.inputs);
        free(tx.outputs);
        dsv_utxo_set_free(utxos);
        dsv_mempool_destroy(&mempool);
        dsv_chain_destroy(&chain);
        FAIL("mempool rejected tx");
    }
    
    /* Mine a block with the transaction */
    dsv_block_t *block = dsv_mine_block_with_txs(&chain, &alice_key.pubkey, 10, &mempool);
    if (!block || !dsv_chain_add_block(&chain, block)) {
        if (block) dsv_block_free(block);
        free(tx.inputs);
        free(tx.outputs);
        dsv_utxo_set_free(utxos);
        dsv_mempool_destroy(&mempool);
        dsv_chain_destroy(&chain);
        FAIL("failed to mine block with tx");
    }
    
    /* Verify Bob has a UTXO */
    dsv_utxo_set_t *bob_utxos = dsv_chain_get_utxos_for_pubkey(&chain, &bob_key.pubkey);
    if (!bob_utxos || bob_utxos->count == 0) {
        dsv_utxo_set_free(bob_utxos);
        dsv_block_free(block);
        free(tx.inputs);
        free(tx.outputs);
        dsv_utxo_set_free(utxos);
        dsv_mempool_destroy(&mempool);
        dsv_chain_destroy(&chain);
        FAIL("Bob should have a UTXO");
    }
    
    dsv_utxo_set_free(bob_utxos);
    dsv_block_free(block);
    free(tx.inputs);
    free(tx.outputs);
    dsv_utxo_set_free(utxos);
    dsv_mempool_destroy(&mempool);
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Chain reorganization
 * ============================================================ */
static void test_reorg(void) {
    TEST("chain reorganization");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    dsv_keypair_t miner_key;
    dsv_keygen(&miner_key);
    
    /* Build initial chain of 5 blocks */
    for (int i = 0; i < 5; i++) {
        dsv_block_t *block = dsv_mine_block(&chain, &miner_key.pubkey, 10);
        dsv_chain_add_block(&chain, block);
        dsv_block_free(block);
    }
    
    /* Save current tip */
    dsv_hash256_t original_tip;
    dsv_chain_get_tip_hash(&chain, &original_tip);
    
    /* Get block at height 3 for forking */
    dsv_block_t *fork_parent = dsv_chain_get_block(&chain, 3);
    if (!fork_parent) {
        dsv_chain_destroy(&chain);
        FAIL("failed to get fork parent");
    }
    
    /* Build a longer competing chain from height 3 */
    dsv_hash256_t fork_prev;
    dsv_block_get_hash(fork_parent, &fork_prev);
    dsv_block_free(fork_parent);
    
    /* Mine 4 blocks on the fork (making it longer than original) */
    dsv_block_t *fork_blocks[4];
    for (int i = 0; i < 4; i++) {
        fork_blocks[i] = dsv_mine_block_on_parent(&chain, &miner_key.pubkey, 
                                                   i == 0 ? &fork_prev : NULL, 10);
        if (!fork_blocks[i]) {
            for (int j = 0; j < i; j++) dsv_block_free(fork_blocks[j]);
            dsv_chain_destroy(&chain);
            FAIL("fork mining failed");
        }
        
        if (i > 0) {
            dsv_block_get_hash(fork_blocks[i-1], &fork_blocks[i]->header.prev_hash);
        }
    }
    
    /* Submit fork blocks - chain should reorg */
    for (int i = 0; i < 4; i++) {
        dsv_chain_add_block(&chain, fork_blocks[i]);
        dsv_block_free(fork_blocks[i]);
    }
    
    /* Verify chain reorganized */
    dsv_hash256_t new_tip;
    dsv_chain_get_tip_hash(&chain, &new_tip);
    
    if (memcmp(new_tip.data, original_tip.data, 32) == 0) {
        dsv_chain_destroy(&chain);
        FAIL("chain should have reorganized");
    }
    
    /* Verify new chain height is 7 (3 common + 4 fork) */
    if (dsv_chain_height(&chain) != 7) {
        dsv_chain_destroy(&chain);
        FAIL("chain height should be 7");
    }
    
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Block validation
 * ============================================================ */
static void test_block_validation(void) {
    TEST("block validation");
    
    cleanup_test_dir();
    
    dsv_chain_t chain;
    if (!dsv_chain_init(&chain, TEST_DIR)) {
        FAIL("chain init failed");
    }
    
    dsv_keypair_t miner_key;
    dsv_keygen(&miner_key);
    
    /* Mine a valid block */
    dsv_block_t *block = dsv_mine_block(&chain, &miner_key.pubkey, 100);
    if (!block) {
        dsv_chain_destroy(&chain);
        FAIL("mining failed");
    }
    
    /* Validate the block */
    dsv_validation_result_t result = dsv_validate_block(&chain, block);
    if (result != DSV_VALID) {
        dsv_block_free(block);
        dsv_chain_destroy(&chain);
        FAIL("valid block rejected");
    }
    
    dsv_block_free(block);
    
    /* Create an invalid block (wrong PoW) */
    dsv_block_t *invalid_block = dsv_mine_block(&chain, &miner_key.pubkey, 1);
    if (invalid_block) {
        /* Corrupt the nonce */
        invalid_block->header.nonce = 0;
        
        result = dsv_validate_block(&chain, invalid_block);
        if (result == DSV_VALID) {
            dsv_block_free(invalid_block);
            dsv_chain_destroy(&chain);
            FAIL("invalid block accepted");
        }
        
        dsv_block_free(invalid_block);
    }
    
    dsv_chain_destroy(&chain);
    cleanup_test_dir();
    PASS();
}

/* ============================================================
 * Test: Persistence and reload
 * ============================================================ */
static void test_persistence(void) {
    TEST("persistence and reload");
    
    cleanup_test_dir();
    
    dsv_hash256_t saved_tip;
    uint32_t saved_height;
    
    /* Create chain and mine some blocks */
    {
        dsv_chain_t chain;
        if (!dsv_chain_init(&chain, TEST_DIR)) {
            FAIL("chain init failed");
        }
        
        dsv_keypair_t miner_key;
        dsv_keygen(&miner_key);
        
        for (int i = 0; i < 10; i++) {
            dsv_block_t *block = dsv_mine_block(&chain, &miner_key.pubkey, 10);
            dsv_chain_add_block(&chain, block);
            dsv_block_free(block);
        }
        
        saved_height = dsv_chain_height(&chain);
        dsv_chain_get_tip_hash(&chain, &saved_tip);
        
        dsv_chain_destroy(&chain);
    }
    
    /* Reload chain and verify state */
    {
        dsv_chain_t chain;
        if (!dsv_chain_init(&chain, TEST_DIR)) {
            FAIL("chain reload failed");
        }
        
        dsv_hash256_t loaded_tip;
        dsv_chain_get_tip_hash(&chain, &loaded_tip);
        
        if (dsv_chain_height(&chain) != saved_height) {
            dsv_chain_destroy(&chain);
            FAIL("height mismatch after reload");
        }
        
        if (memcmp(loaded_tip.data, saved_tip.data, 32) != 0) {
            dsv_chain_destroy(&chain);
            FAIL("tip mismatch after reload");
        }
        
        dsv_chain_destroy(&chain);
    }
    
    cleanup_test_dir();
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
    
    printf("DSV Chain Integration Tests\n");
    printf("===========================\n\n");
    
    test_genesis_creation();
    test_mining();
    test_mining_multiple();
    test_spending();
    test_reorg();
    test_block_validation();
    test_persistence();
    
    /* Summary */
    printf("\n===========================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    /* Final cleanup */
    cleanup_test_dir();
    
    return (tests_passed == tests_run) ? 0 : 1;
}

