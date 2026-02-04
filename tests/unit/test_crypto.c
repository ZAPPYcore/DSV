/**
 * DSV Cryptographic Unit Tests
 * 
 * Tests for SHA-256, Ed25519, and related crypto operations.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
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
 * Test: SHA-256 empty string
 * ============================================================ */
static void test_sha256_empty(void) {
    TEST("SHA-256 empty string");
    
    dsv_hash256_t hash;
    dsv_sha256(&hash, NULL, 0);
    
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    const uint8_t expected[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    
    if (memcmp(hash.data, expected, 32) != 0) {
        FAIL("hash mismatch");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: SHA-256 known value
 * ============================================================ */
static void test_sha256_known(void) {
    TEST("SHA-256 known value");
    
    const char *input = "hello";
    dsv_hash256_t hash;
    dsv_sha256(&hash, (const uint8_t *)input, strlen(input));
    
    /* SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 */
    const uint8_t expected[] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
    };
    
    if (memcmp(hash.data, expected, 32) != 0) {
        FAIL("hash mismatch");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Double SHA-256
 * ============================================================ */
static void test_double_sha256(void) {
    TEST("double SHA-256");
    
    const char *input = "test";
    dsv_hash256_t hash;
    dsv_hash256(&hash, (const uint8_t *)input, strlen(input));
    
    /* Double SHA-256 should differ from single SHA-256 */
    dsv_hash256_t single;
    dsv_sha256(&single, (const uint8_t *)input, strlen(input));
    
    if (memcmp(hash.data, single.data, 32) == 0) {
        FAIL("double hash should differ from single");
        return;
    }
    
    /* Verify by computing manually */
    dsv_hash256_t verify;
    dsv_sha256(&verify, single.data, 32);
    
    if (memcmp(hash.data, verify.data, 32) != 0) {
        FAIL("double hash mismatch");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 key generation
 * ============================================================ */
static void test_ed25519_keygen(void) {
    TEST("Ed25519 key generation");
    
    dsv_seed_t seed;
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    
    dsv_generate_seed(&seed);
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    /* Verify keys are not all zeros */
    bool pubkey_zero = true;
    bool privkey_zero = true;
    
    for (int i = 0; i < 32; i++) {
        if (pubkey.data[i] != 0) pubkey_zero = false;
        if (privkey.data[i] != 0) privkey_zero = false;
    }
    
    if (pubkey_zero) {
        FAIL("public key is all zeros");
        return;
    }
    
    if (privkey_zero) {
        FAIL("private key is all zeros");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 sign and verify
 * ============================================================ */
static void test_ed25519_sign_verify(void) {
    TEST("Ed25519 sign and verify");
    
    dsv_seed_t seed;
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    
    dsv_generate_seed(&seed);
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    const char *message = "This is a test message";
    dsv_signature_t sig;
    
    dsv_sign(&sig, (const uint8_t *)message, strlen(message), &privkey);
    
    if (!dsv_verify(&sig, (const uint8_t *)message, strlen(message), &pubkey)) {
        FAIL("verification failed");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 invalid signature
 * ============================================================ */
static void test_ed25519_invalid_sig(void) {
    TEST("Ed25519 invalid signature");
    
    dsv_seed_t seed;
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    
    dsv_generate_seed(&seed);
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    const char *message = "This is a test message";
    dsv_signature_t sig;
    
    dsv_sign(&sig, (const uint8_t *)message, strlen(message), &privkey);
    
    /* Corrupt the signature */
    sig.data[0] ^= 0xFF;
    
    if (dsv_verify(&sig, (const uint8_t *)message, strlen(message), &pubkey)) {
        FAIL("corrupted signature should not verify");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 wrong message
 * ============================================================ */
static void test_ed25519_wrong_message(void) {
    TEST("Ed25519 wrong message");
    
    dsv_seed_t seed;
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    
    dsv_generate_seed(&seed);
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    const char *message1 = "Message 1";
    const char *message2 = "Message 2";
    dsv_signature_t sig;
    
    dsv_sign(&sig, (const uint8_t *)message1, strlen(message1), &privkey);
    
    if (dsv_verify(&sig, (const uint8_t *)message2, strlen(message2), &pubkey)) {
        FAIL("signature should not verify for different message");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 wrong key
 * ============================================================ */
static void test_ed25519_wrong_key(void) {
    TEST("Ed25519 wrong key");
    
    dsv_seed_t seed1, seed2;
    dsv_privkey_t privkey1, privkey2;
    dsv_pubkey_t pubkey1, pubkey2;
    
    dsv_generate_seed(&seed1);
    dsv_keypair_from_seed(&privkey1, &pubkey1, &seed1);
    
    dsv_generate_seed(&seed2);
    dsv_keypair_from_seed(&privkey2, &pubkey2, &seed2);
    
    const char *message = "Test message";
    dsv_signature_t sig;
    
    dsv_sign(&sig, (const uint8_t *)message, strlen(message), &privkey1);
    
    if (dsv_verify(&sig, (const uint8_t *)message, strlen(message), &pubkey2)) {
        FAIL("signature should not verify with different key");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Ed25519 deterministic
 * ============================================================ */
static void test_ed25519_deterministic(void) {
    TEST("Ed25519 deterministic");
    
    dsv_seed_t seed;
    dsv_privkey_t privkey;
    dsv_pubkey_t pubkey;
    
    dsv_generate_seed(&seed);
    dsv_keypair_from_seed(&privkey, &pubkey, &seed);
    
    const char *message = "Deterministic test";
    dsv_signature_t sig1, sig2;
    
    dsv_sign(&sig1, (const uint8_t *)message, strlen(message), &privkey);
    dsv_sign(&sig2, (const uint8_t *)message, strlen(message), &privkey);
    
    /* Ed25519 signatures are deterministic */
    if (memcmp(sig1.data, sig2.data, 64) != 0) {
        FAIL("same message should produce same signature");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Secure memory zeroing
 * ============================================================ */
static void test_secure_zero(void) {
    TEST("secure memory zeroing");
    
    uint8_t buffer[64];
    memset(buffer, 0xAA, sizeof(buffer));
    
    dsv_secure_zero(buffer, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            FAIL("buffer not zeroed");
            return;
        }
    }
    
    PASS();
}

/* ============================================================
 * Test: Secure comparison - equal
 * ============================================================ */
static void test_secure_cmp_equal(void) {
    TEST("secure comparison equal");
    
    uint8_t a[32], b[32];
    memset(a, 0x42, sizeof(a));
    memset(b, 0x42, sizeof(b));
    
    if (!dsv_secure_compare(a, b, sizeof(a))) {
        FAIL("equal buffers should compare as equal");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Secure comparison - not equal
 * ============================================================ */
static void test_secure_cmp_not_equal(void) {
    TEST("secure comparison not equal");
    
    uint8_t a[32], b[32];
    memset(a, 0x42, sizeof(a));
    memset(b, 0x43, sizeof(b));
    
    if (dsv_secure_compare(a, b, sizeof(a))) {
        FAIL("different buffers should compare as not equal");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Random bytes
 * ============================================================ */
static void test_random_bytes(void) {
    TEST("random bytes");
    
    uint8_t buffer1[32], buffer2[32];
    
    dsv_random_bytes(buffer1, sizeof(buffer1));
    dsv_random_bytes(buffer2, sizeof(buffer2));
    
    /* Extremely unlikely to be equal */
    if (memcmp(buffer1, buffer2, sizeof(buffer1)) == 0) {
        FAIL("two random buffers should differ");
        return;
    }
    
    /* Extremely unlikely to be all zeros */
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(buffer1); i++) {
        if (buffer1[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        FAIL("random buffer should not be all zeros");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Hash160 (Blake2b truncated)
 * ============================================================ */
static void test_hash160(void) {
    TEST("hash160");
    
    const char *input = "test pubkey data";
    uint8_t hash[20];
    
    dsv_hash160(hash, (const uint8_t *)input, strlen(input));
    
    /* Verify not all zeros */
    bool all_zero = true;
    for (int i = 0; i < 20; i++) {
        if (hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        FAIL("hash160 should not be all zeros");
        return;
    }
    
    /* Verify deterministic */
    uint8_t hash2[20];
    dsv_hash160(hash2, (const uint8_t *)input, strlen(input));
    
    if (memcmp(hash, hash2, 20) != 0) {
        FAIL("hash160 should be deterministic");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void) {
    /* Initialize crypto library */
    if (dsv_crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto library\n");
        return 1;
    }
    
    printf("DSV Crypto Unit Tests\n");
    printf("=====================\n\n");
    
    /* SHA-256 */
    test_sha256_empty();
    test_sha256_known();
    test_double_sha256();
    
    /* Ed25519 */
    test_ed25519_keygen();
    test_ed25519_sign_verify();
    test_ed25519_invalid_sig();
    test_ed25519_wrong_message();
    test_ed25519_wrong_key();
    test_ed25519_deterministic();
    
    /* Utility functions */
    test_secure_zero();
    test_secure_cmp_equal();
    test_secure_cmp_not_equal();
    test_random_bytes();
    test_hash160();
    
    /* Summary */
    printf("\n=====================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return (tests_passed == tests_run) ? 0 : 1;
}

