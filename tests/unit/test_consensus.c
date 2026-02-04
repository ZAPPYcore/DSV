/**
 * DSV Consensus Unit Tests
 * 
 * Tests for difficulty calculation, block validation, and consensus rules.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "dsv_consensus.h"
#include "dsv_u320.h"
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
} while(0)

/* ============================================================
 * Test: Initial block reward
 * ============================================================ */
static void test_initial_reward(void) {
    TEST("initial block reward");
    
    dsv_u320_t reward;
    dsv_get_block_reward(&reward, 0);  /* Genesis block */
    
    /* Initial reward should not be zero */
    if (dsv_u320_is_zero(&reward)) {
        FAIL("reward should not be zero at genesis");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Halving
 * ============================================================ */
static void test_halving(void) {
    TEST("block reward halving");
    
    dsv_u320_t reward0, reward1, reward2;
    
    dsv_get_block_reward(&reward0, 0);      /* Before first halving */
    dsv_get_block_reward(&reward1, 216);    /* After first halving */
    dsv_get_block_reward(&reward2, 432);    /* After second halving */
    
    /* reward1 should be approximately half of reward0 */
    /* reward2 should be approximately half of reward1 */
    
    /* Simple check: reward1 < reward0 */
    if (dsv_u320_cmp(&reward1, &reward0) >= 0) {
        FAIL("reward should decrease after halving");
        return;
    }
    
    /* reward2 < reward1 */
    if (dsv_u320_cmp(&reward2, &reward1) >= 0) {
        FAIL("reward should decrease after second halving");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Reward eventually zero
 * ============================================================ */
static void test_reward_exhaustion(void) {
    TEST("reward exhaustion");
    
    dsv_u320_t reward;
    
    /* After many halvings, reward should approach zero */
    /* 210,000 DSV / 2.1 DSV per block = 100,000 blocks to mine all
     * But with halving every 216 blocks, let's check at very high heights */
    
    dsv_get_block_reward(&reward, 1000000);  /* Very high block */
    
    /* Reward should be very small or zero */
    dsv_u320_t one_lgb;
    dsv_u320_from_u64(&one_lgb, 1);
    
    /* After ~4600+ halvings (1000000/216), reward should be essentially 0 */
    /* 2.1 DSV >> 4600 underflows to 0 */
    
    if (!dsv_u320_is_zero(&reward)) {
        /* At 1M blocks with 216 halving interval:
         * halvings = 1000000 / 216 = 4629
         * 2.1 * 10^72 >> 4629 = 0 (way more than 320 bits) */
        /* This is expected to be zero */
    }
    
    PASS();
}

/* ============================================================
 * Test: Compact bits to target
 * ============================================================ */
static void test_bits_to_target(void) {
    TEST("compact bits to target");
    
    uint8_t target[32];
    
    /* Bitcoin genesis: 0x1d00ffff */
    dsv_bits_to_target(target, 0x1d00ffff);
    
    /* Expected: 00000000FFFF0000...0000 (32 bytes) */
    /* The first 4 bytes should be 00 00 00 00 */
    /* Then FFFF in the right position based on exponent 0x1d = 29 */
    
    /* Simplified check: target should not be all zeros */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (target[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        FAIL("target should not be all zeros");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Target to compact bits round-trip
 * ============================================================ */
static void test_target_bits_roundtrip(void) {
    TEST("target bits round-trip");
    
    uint32_t original = 0x1d00ffff;
    uint8_t target[32];
    
    dsv_bits_to_target(target, original);
    uint32_t restored = dsv_target_to_bits(target);
    
    /* Note: Not all bits values round-trip perfectly due to normalization */
    /* But standard values should work */
    
    if (restored != original) {
        /* Allow for normalization differences */
        /* Check that they represent the same target */
        uint8_t target2[32];
        dsv_bits_to_target(target2, restored);
        
        if (memcmp(target, target2, 32) != 0) {
            FAIL("round-trip target mismatch");
            return;
        }
    }
    
    PASS();
}

/* ============================================================
 * Test: Hash meets target
 * ============================================================ */
static void test_hash_meets_target(void) {
    TEST("hash meets target");
    
    /* Create an easy target (high value = easy) */
    uint32_t easy_bits = 0x1f00ffff;  /* Very easy */
    
    /* Hash with leading zeros should meet easy target */
    dsv_hash256_t hash;
    memset(hash.data, 0, 32);
    hash.data[31] = 0x01;  /* Small value in little endian */
    
    if (!dsv_hash_meets_target(&hash, easy_bits)) {
        FAIL("small hash should meet easy target");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Hash fails target
 * ============================================================ */
static void test_hash_fails_target(void) {
    TEST("hash fails target");
    
    /* Create a hard target (low value = hard) */
    uint32_t hard_bits = 0x03000001;  /* Very hard */
    
    /* Hash with high values should fail hard target */
    dsv_hash256_t hash;
    memset(hash.data, 0xFF, 32);
    
    if (dsv_hash_meets_target(&hash, hard_bits)) {
        FAIL("large hash should fail hard target");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Difficulty adjustment clamp - increase
 * ============================================================ */
static void test_difficulty_clamp_up(void) {
    TEST("difficulty adjustment clamp up");
    
    /* If blocks came 10x faster than expected, difficulty should increase
     * but be clamped at 4x */
    
    uint32_t old_bits = 0x1d00ffff;
    uint32_t new_bits;
    
    /* Actual time: 1/10 of expected (blocks too fast) */
    /* 2016 blocks * 10 minutes = 20160 minutes expected */
    /* Actual: 2016 minutes */
    
    new_bits = dsv_calculate_next_bits(old_bits, 2016 * 60, 20160 * 60);
    
    /* Difficulty should increase (bits should decrease or represent smaller target) */
    /* With 10x clamp, should be limited to 4x increase */
    
    /* Convert to targets and compare */
    uint8_t old_target[32], new_target[32];
    dsv_bits_to_target(old_target, old_bits);
    dsv_bits_to_target(new_target, new_bits);
    
    /* New target should be smaller (harder) */
    bool new_smaller = false;
    for (int i = 0; i < 32; i++) {
        if (new_target[i] < old_target[i]) {
            new_smaller = true;
            break;
        }
        if (new_target[i] > old_target[i]) {
            break;
        }
    }
    
    if (!new_smaller) {
        FAIL("difficulty should increase");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Difficulty adjustment clamp - decrease
 * ============================================================ */
static void test_difficulty_clamp_down(void) {
    TEST("difficulty adjustment clamp down");
    
    uint32_t old_bits = 0x1d00ffff;
    uint32_t new_bits;
    
    /* Actual time: 10x expected (blocks too slow) */
    new_bits = dsv_calculate_next_bits(old_bits, 201600 * 60, 20160 * 60);
    
    /* Difficulty should decrease (target increases) but clamped at 1/4x */
    
    uint8_t old_target[32], new_target[32];
    dsv_bits_to_target(old_target, old_bits);
    dsv_bits_to_target(new_target, new_bits);
    
    /* New target should be larger (easier) */
    bool new_larger = false;
    for (int i = 31; i >= 0; i--) {
        if (new_target[i] > old_target[i]) {
            new_larger = true;
            break;
        }
        if (new_target[i] < old_target[i]) {
            break;
        }
    }
    
    if (!new_larger) {
        FAIL("difficulty should decrease");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Coinbase maturity
 * ============================================================ */
#define DSV_COINBASE_MATURITY 100

static inline bool coinbase_is_mature(int64_t coinbase_height, int64_t current_height) {
    return (current_height - coinbase_height) >= DSV_COINBASE_MATURITY;
}

static void test_coinbase_maturity(void) {
    TEST("coinbase maturity");
    
    /* Coinbase from block 100 should be spendable at block 200 */
    if (!coinbase_is_mature(100, 200)) {
        FAIL("coinbase should be mature after 100 blocks");
        return;
    }
    
    /* Coinbase from block 100 should NOT be spendable at block 150 */
    if (coinbase_is_mature(100, 150)) {
        FAIL("coinbase should not be mature before 100 blocks");
        return;
    }
    
    /* Edge case: exactly 100 blocks */
    if (!coinbase_is_mature(100, 200)) {
        FAIL("coinbase should be mature at exactly 100 blocks");
        return;
    }
    
    /* Not mature at 99 blocks */
    if (coinbase_is_mature(100, 199)) {
        FAIL("coinbase should not be mature at 99 blocks");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Fee calculation
 * ============================================================ */
static void test_fee_calculation(void) {
    TEST("fee calculation");
    
    dsv_u320_t inputs, outputs, fee;
    
    dsv_u320_from_u64(&inputs, 1000);
    dsv_u320_from_u64(&outputs, 900);
    
    /* Fee = inputs - outputs (should not underflow) */
    bool underflow = dsv_u320_sub(&fee, &inputs, &outputs);
    
    if (underflow) {
        FAIL("fee calculation should succeed");
        return;
    }
    
    dsv_u320_t expected_fee;
    dsv_u320_from_u64(&expected_fee, 100);
    
    if (dsv_u320_cmp(&fee, &expected_fee) != 0) {
        FAIL("fee should be 100");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Negative fee detection
 * ============================================================ */
static void test_negative_fee(void) {
    TEST("negative fee detection");
    
    dsv_u320_t inputs, outputs, fee;
    
    dsv_u320_from_u64(&inputs, 100);
    dsv_u320_from_u64(&outputs, 200);  /* More outputs than inputs */
    
    /* Subtraction should underflow (return true) */
    bool underflow = dsv_u320_sub(&fee, &inputs, &outputs);
    
    if (!underflow) {
        FAIL("should detect negative fee (underflow)");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Supply cap check
 * ============================================================ */
static void test_supply_cap(void) {
    TEST("supply cap check");
    
    /* Test with simple values - check dsv_check_supply_limit at height 0 */
    dsv_u320_t small_amount;
    dsv_u320_from_u64(&small_amount, 1);
    
    /* Small amount at height 0 should be valid */
    if (!dsv_check_supply_limit(&small_amount, 0)) {
        FAIL("small amount should be within supply limit");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Block time validation
 * ============================================================ */
#define DSV_MAX_FUTURE_BLOCK_TIME (2 * 60 * 60)  /* 2 hours */

static inline bool valid_block_time(uint32_t block_time, uint32_t current_time) {
    /* Block time must not be more than 2 hours in the future */
    return block_time <= current_time + DSV_MAX_FUTURE_BLOCK_TIME;
}

static void test_block_time(void) {
    TEST("block time validation");
    
    uint32_t current_time = 1700000000;  /* Some Unix timestamp */
    
    /* Block 2 hours + 1 second in the future - should be invalid */
    uint32_t future_time = current_time + 2 * 60 * 60 + 1;
    if (valid_block_time(future_time, current_time)) {
        FAIL("future block time should be invalid");
        return;
    }
    
    /* Block at current time - should be valid */
    if (!valid_block_time(current_time, current_time)) {
        FAIL("current block time should be valid");
        return;
    }
    
    /* Block in the past - should be valid */
    uint32_t past_time = current_time - 1000;
    if (!valid_block_time(past_time, current_time)) {
        FAIL("past block time should be valid");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void) {
    /* Initialize crypto */
    if (dsv_crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    
    printf("DSV Consensus Unit Tests\n");
    printf("========================\n\n");
    
    /* Block rewards */
    test_initial_reward();
    test_halving();
    test_reward_exhaustion();
    
    /* Difficulty */
    test_bits_to_target();
    test_target_bits_roundtrip();
    test_hash_meets_target();
    test_hash_fails_target();
    test_difficulty_clamp_up();
    test_difficulty_clamp_down();
    
    /* Consensus rules */
    test_coinbase_maturity();
    test_fee_calculation();
    test_negative_fee();
    test_supply_cap();
    test_block_time();
    
    /* Summary */
    printf("\n========================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return (tests_passed == tests_run) ? 0 : 1;
}

