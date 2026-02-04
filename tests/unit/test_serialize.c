/**
 * DSV Serialization Unit Tests
 * 
 * Tests for transaction and block serialization.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dsv_serialize.h"
#include "dsv_crypto.h"
#include "dsv_u320.h"

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
 * Test: Buffer creation
 * ============================================================ */
static void test_buffer_create(void) {
    TEST("buffer creation");
    
    dsv_buffer_t *buf = dsv_buffer_new(1024);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    if (buf->size < 1024) {
        dsv_buffer_free(buf);
        FAIL("buffer size too small");
        return;
    }
    
    if (buf->pos != 0) {
        dsv_buffer_free(buf);
        FAIL("buffer position should start at 0");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read u8
 * ============================================================ */
static void test_write_read_u8(void) {
    TEST("write/read u8");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    if (!dsv_write_u8(buf, 0x42)) {
        dsv_buffer_free(buf);
        FAIL("failed to write u8");
        return;
    }
    
    if (!dsv_write_u8(buf, 0xFF)) {
        dsv_buffer_free(buf);
        FAIL("failed to write second u8");
        return;
    }
    
    /* Reset position for reading */
    buf->pos = 0;
    
    uint8_t val1, val2;
    if (!dsv_read_u8(buf, &val1) || val1 != 0x42) {
        dsv_buffer_free(buf);
        FAIL("failed to read first u8");
        return;
    }
    
    if (!dsv_read_u8(buf, &val2) || val2 != 0xFF) {
        dsv_buffer_free(buf);
        FAIL("failed to read second u8");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read u32
 * ============================================================ */
static void test_write_read_u32(void) {
    TEST("write/read u32");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    uint32_t test_val = 0x12345678;
    if (!dsv_write_u32(buf, test_val)) {
        dsv_buffer_free(buf);
        FAIL("failed to write u32");
        return;
    }
    
    buf->pos = 0;
    
    uint32_t read_val;
    if (!dsv_read_u32(buf, &read_val)) {
        dsv_buffer_free(buf);
        FAIL("failed to read u32");
        return;
    }
    
    if (read_val != test_val) {
        dsv_buffer_free(buf);
        FAIL("u32 value mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read u64
 * ============================================================ */
static void test_write_read_u64(void) {
    TEST("write/read u64");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    uint64_t test_val = 0x123456789ABCDEF0ULL;
    if (!dsv_write_u64(buf, test_val)) {
        dsv_buffer_free(buf);
        FAIL("failed to write u64");
        return;
    }
    
    buf->pos = 0;
    
    uint64_t read_val;
    if (!dsv_read_u64(buf, &read_val)) {
        dsv_buffer_free(buf);
        FAIL("failed to read u64");
        return;
    }
    
    if (read_val != test_val) {
        dsv_buffer_free(buf);
        FAIL("u64 value mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read varint
 * ============================================================ */
static void test_varint(void) {
    TEST("varint encoding");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    /* Test small value (single byte) */
    if (!dsv_write_varint(buf, 100)) {
        dsv_buffer_free(buf);
        FAIL("failed to write small varint");
        return;
    }
    
    /* Test medium value (3 bytes: 0xFD prefix + 2 bytes) */
    if (!dsv_write_varint(buf, 1000)) {
        dsv_buffer_free(buf);
        FAIL("failed to write medium varint");
        return;
    }
    
    /* Test large value */
    if (!dsv_write_varint(buf, 0x100000000ULL)) {
        dsv_buffer_free(buf);
        FAIL("failed to write large varint");
        return;
    }
    
    buf->pos = 0;
    
    uint64_t val1, val2, val3;
    if (!dsv_read_varint(buf, &val1) || val1 != 100) {
        dsv_buffer_free(buf);
        FAIL("failed to read small varint");
        return;
    }
    
    if (!dsv_read_varint(buf, &val2) || val2 != 1000) {
        dsv_buffer_free(buf);
        FAIL("failed to read medium varint");
        return;
    }
    
    if (!dsv_read_varint(buf, &val3) || val3 != 0x100000000ULL) {
        dsv_buffer_free(buf);
        FAIL("failed to read large varint");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read bytes
 * ============================================================ */
static void test_write_read_bytes(void) {
    TEST("write/read bytes");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    uint8_t test_data[16];
    for (int i = 0; i < 16; i++) {
        test_data[i] = (uint8_t)(i * 3);
    }
    
    if (!dsv_write_bytes(buf, test_data, 16)) {
        dsv_buffer_free(buf);
        FAIL("failed to write bytes");
        return;
    }
    
    buf->pos = 0;
    
    uint8_t read_data[16];
    if (!dsv_read_bytes(buf, read_data, 16)) {
        dsv_buffer_free(buf);
        FAIL("failed to read bytes");
        return;
    }
    
    if (memcmp(test_data, read_data, 16) != 0) {
        dsv_buffer_free(buf);
        FAIL("bytes mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Write and read hash
 * ============================================================ */
static void test_write_read_hash(void) {
    TEST("write/read hash");
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    dsv_hash256_t test_hash;
    for (int i = 0; i < 32; i++) {
        test_hash.data[i] = (uint8_t)(i + 0x10);
    }
    
    if (!dsv_write_hash(buf, &test_hash)) {
        dsv_buffer_free(buf);
        FAIL("failed to write hash");
        return;
    }
    
    buf->pos = 0;
    
    dsv_hash256_t read_hash;
    if (!dsv_read_hash(buf, &read_hash)) {
        dsv_buffer_free(buf);
        FAIL("failed to read hash");
        return;
    }
    
    if (memcmp(test_hash.data, read_hash.data, 32) != 0) {
        dsv_buffer_free(buf);
        FAIL("hash mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: Block header serialization
 * ============================================================ */
static void test_block_header_serialize(void) {
    TEST("block header serialize");
    
    dsv_block_header_t header = {0};
    header.version = 1;
    header.timestamp = 1700000000;
    header.bits = 0x1d00ffff;
    header.nonce = 12345;
    
    /* Set prev_hash and merkle_root */
    for (int i = 0; i < 32; i++) {
        header.prev_hash.data[i] = (uint8_t)i;
        header.merkle_root.data[i] = (uint8_t)(255 - i);
    }
    
    dsv_buffer_t *buf = dsv_buffer_new(DSV_BLOCK_HEADER_SIZE + 16);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    if (!dsv_block_header_serialize(buf, &header)) {
        dsv_buffer_free(buf);
        FAIL("failed to serialize block header");
        return;
    }
    
    if (buf->pos != DSV_BLOCK_HEADER_SIZE) {
        dsv_buffer_free(buf);
        FAIL("unexpected serialized size");
        return;
    }
    
    buf->pos = 0;
    
    dsv_block_header_t restored;
    if (!dsv_block_header_deserialize(buf, &restored)) {
        dsv_buffer_free(buf);
        FAIL("failed to deserialize block header");
        return;
    }
    
    if (header.version != restored.version ||
        header.timestamp != restored.timestamp ||
        header.bits != restored.bits ||
        header.nonce != restored.nonce) {
        dsv_buffer_free(buf);
        FAIL("header fields mismatch");
        return;
    }
    
    if (memcmp(header.prev_hash.data, restored.prev_hash.data, 32) != 0 ||
        memcmp(header.merkle_root.data, restored.merkle_root.data, 32) != 0) {
        dsv_buffer_free(buf);
        FAIL("header hashes mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
    PASS();
}

/* ============================================================
 * Test: U320 serialization
 * ============================================================ */
static void test_u320_serialize(void) {
    TEST("u320 serialize");
    
    dsv_u320_t original;
    dsv_u320_from_u64(&original, 0x123456789ABCDEF0ULL);
    
    dsv_buffer_t *buf = dsv_buffer_new(64);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    
    if (!dsv_write_u320(buf, &original)) {
        dsv_buffer_free(buf);
        FAIL("failed to serialize u320");
        return;
    }
    
    buf->pos = 0;
    
    dsv_u320_t restored;
    if (!dsv_read_u320(buf, &restored)) {
        dsv_buffer_free(buf);
        FAIL("failed to deserialize u320");
        return;
    }
    
    if (dsv_u320_cmp(&original, &restored) != 0) {
        dsv_buffer_free(buf);
        FAIL("u320 value mismatch");
        return;
    }
    
    dsv_buffer_free(buf);
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
    
    printf("DSV Serialization Unit Tests\n");
    printf("============================\n\n");
    
    /* Buffer tests */
    test_buffer_create();
    
    /* Primitive serialization */
    test_write_read_u8();
    test_write_read_u32();
    test_write_read_u64();
    test_varint();
    test_write_read_bytes();
    test_write_read_hash();
    
    /* Composite serialization */
    test_block_header_serialize();
    test_u320_serialize();
    
    /* Summary */
    printf("\n============================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return (tests_passed == tests_run) ? 0 : 1;
}
