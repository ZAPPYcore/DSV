/**
 * DSV 320-bit Integer Unit Tests
 * 
 * Tests for dsv_u320_t operations including arithmetic,
 * comparison, and serialization.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
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
 * Test: Zero value
 * ============================================================ */
static void test_zero(void) {
    TEST("zero value");
    
    dsv_u320_t zero;
    dsv_u320_from_u64(&zero, 0);
    
    if (!dsv_u320_is_zero(&zero)) {
        FAIL("zero should be zero");
        return;
    }
    
    for (int i = 0; i < 5; i++) {
        if (zero.parts[i] != 0) {
            FAIL("zero parts should all be 0");
            return;
        }
    }
    
    PASS();
}

/* ============================================================
 * Test: Set from u64
 * ============================================================ */
static void test_from_u64(void) {
    TEST("from u64");
    
    dsv_u320_t value;
    dsv_u320_from_u64(&value, 0x123456789ABCDEF0ULL);
    
    if (value.parts[0] != 0x123456789ABCDEF0ULL) {
        FAIL("parts[0] mismatch");
        return;
    }
    
    for (int i = 1; i < 5; i++) {
        if (value.parts[i] != 0) {
            FAIL("upper parts should be zero");
            return;
        }
    }
    
    PASS();
}

/* ============================================================
 * Test: Comparison - equal
 * ============================================================ */
static void test_cmp_equal(void) {
    TEST("comparison equal");
    
    dsv_u320_t a, b;
    dsv_u320_from_u64(&a, 12345);
    dsv_u320_from_u64(&b, 12345);
    
    if (dsv_u320_cmp(&a, &b) != 0) {
        FAIL("equal values should compare as 0");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Comparison - less than
 * ============================================================ */
static void test_cmp_less(void) {
    TEST("comparison less than");
    
    dsv_u320_t a, b;
    dsv_u320_from_u64(&a, 100);
    dsv_u320_from_u64(&b, 200);
    
    if (dsv_u320_cmp(&a, &b) >= 0) {
        FAIL("100 should be less than 200");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Comparison - greater than
 * ============================================================ */
static void test_cmp_greater(void) {
    TEST("comparison greater than");
    
    dsv_u320_t a, b;
    dsv_u320_from_u64(&a, 200);
    dsv_u320_from_u64(&b, 100);
    
    if (dsv_u320_cmp(&a, &b) <= 0) {
        FAIL("200 should be greater than 100");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Comparison - upper bits
 * ============================================================ */
static void test_cmp_upper_bits(void) {
    TEST("comparison upper bits");
    
    dsv_u320_t a, b;
    dsv_u320_from_u64(&a, 0);
    dsv_u320_from_u64(&b, 0);
    
    /* a has larger value in upper bits */
    a.parts[4] = 1;
    b.parts[0] = UINT64_MAX;
    
    if (dsv_u320_cmp(&a, &b) <= 0) {
        FAIL("upper bit value should be greater");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Addition - simple
 * ============================================================ */
static void test_add_simple(void) {
    TEST("addition simple");
    
    dsv_u320_t a, b, result;
    dsv_u320_from_u64(&a, 100);
    dsv_u320_from_u64(&b, 200);
    
    bool overflow = dsv_u320_add(&result, &a, &b);
    
    if (overflow) {
        FAIL("should not overflow");
        return;
    }
    
    if (result.parts[0] != 300) {
        FAIL("100 + 200 should equal 300");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Addition - with carry
 * ============================================================ */
static void test_add_carry(void) {
    TEST("addition with carry");
    
    dsv_u320_t a, b, result;
    dsv_u320_from_u64(&a, 0);
    dsv_u320_from_u64(&b, 0);
    
    a.parts[0] = UINT64_MAX;
    b.parts[0] = 1;
    
    bool overflow = dsv_u320_add(&result, &a, &b);
    
    if (overflow) {
        FAIL("should not overflow");
        return;
    }
    
    if (result.parts[0] != 0 || result.parts[1] != 1) {
        FAIL("carry not propagated correctly");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Addition - overflow
 * ============================================================ */
static void test_add_overflow(void) {
    TEST("addition overflow");
    
    dsv_u320_t a, b, result;
    
    /* Set all bits to max */
    for (int i = 0; i < 5; i++) {
        a.parts[i] = UINT64_MAX;
    }
    dsv_u320_from_u64(&b, 1);
    
    bool overflow = dsv_u320_add(&result, &a, &b);
    
    if (!overflow) {
        FAIL("should overflow");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Subtraction - simple
 * ============================================================ */
static void test_sub_simple(void) {
    TEST("subtraction simple");
    
    dsv_u320_t a, b, result;
    dsv_u320_from_u64(&a, 300);
    dsv_u320_from_u64(&b, 100);
    
    bool underflow = dsv_u320_sub(&result, &a, &b);
    
    if (underflow) {
        FAIL("should not underflow");
        return;
    }
    
    if (result.parts[0] != 200) {
        FAIL("300 - 100 should equal 200");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Subtraction - with borrow
 * ============================================================ */
static void test_sub_borrow(void) {
    TEST("subtraction with borrow");
    
    dsv_u320_t a, b, result;
    dsv_u320_from_u64(&a, 0);
    dsv_u320_from_u64(&b, 0);
    
    a.parts[0] = 0;
    a.parts[1] = 1;  /* a = 2^64 */
    b.parts[0] = 1;  /* b = 1 */
    
    bool underflow = dsv_u320_sub(&result, &a, &b);
    
    if (underflow) {
        FAIL("should not underflow");
        return;
    }
    
    if (result.parts[0] != UINT64_MAX || result.parts[1] != 0) {
        FAIL("borrow not handled correctly");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Subtraction - underflow
 * ============================================================ */
static void test_sub_underflow(void) {
    TEST("subtraction underflow");
    
    dsv_u320_t a, b, result;
    dsv_u320_from_u64(&a, 100);
    dsv_u320_from_u64(&b, 200);
    
    bool underflow = dsv_u320_sub(&result, &a, &b);
    
    if (!underflow) {
        FAIL("should underflow");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Serialization round-trip
 * ============================================================ */
static void test_serialize_roundtrip(void) {
    TEST("serialization round-trip");
    
    dsv_u320_t original, restored;
    uint8_t buffer[40];
    
    /* Set some interesting values */
    original.parts[0] = 0x123456789ABCDEF0ULL;
    original.parts[1] = 0xFEDCBA9876543210ULL;
    original.parts[2] = 0x1111222233334444ULL;
    original.parts[3] = 0x5555666677778888ULL;
    original.parts[4] = 0x9999AAAABBBBCCCCULL;
    
    dsv_u320_to_bytes(&original, buffer);
    dsv_u320_from_bytes(&restored, buffer);
    
    if (dsv_u320_cmp(&original, &restored) != 0) {
        FAIL("round-trip failed");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Serialization - little endian
 * ============================================================ */
static void test_serialize_little_endian(void) {
    TEST("serialization little endian");
    
    dsv_u320_t value;
    uint8_t buffer[40];
    
    dsv_u320_from_u64(&value, 0x0102030405060708ULL);
    dsv_u320_to_bytes(&value, buffer);
    
    /* Little endian: least significant byte first */
    if (buffer[0] != 0x08 || buffer[1] != 0x07 || 
        buffer[2] != 0x06 || buffer[3] != 0x05 ||
        buffer[4] != 0x04 || buffer[5] != 0x03 ||
        buffer[6] != 0x02 || buffer[7] != 0x01) {
        FAIL("not little endian");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Large number multiplication
 * ============================================================ */
static void test_mul_u64(void) {
    TEST("multiplication u64");
    
    dsv_u320_t value, result;
    dsv_u320_from_u64(&value, 1000000);
    
    bool overflow = dsv_u320_mul_u64(&result, &value, 1000000);
    
    if (overflow) {
        FAIL("should not overflow");
        return;
    }
    
    /* 1000000 * 1000000 = 10^12 */
    if (result.parts[0] != 1000000000000ULL) {
        FAIL("multiplication result wrong");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Test: Division by u64
 * ============================================================ */
static void test_div_u64(void) {
    TEST("division u64");
    
    dsv_u320_t value, quotient;
    uint64_t remainder;
    
    dsv_u320_from_u64(&value, 1000);
    
    bool success = dsv_u320_div_u64(&quotient, &remainder, &value, 7);
    
    if (!success) {
        FAIL("division failed");
        return;
    }
    
    /* 1000 / 7 = 142, remainder 6 */
    if (quotient.parts[0] != 142 || remainder != 6) {
        FAIL("division result wrong");
        return;
    }
    
    PASS();
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void) {
    printf("DSV U320 Unit Tests\n");
    printf("===================\n\n");
    
    /* Zero and initialization */
    test_zero();
    test_from_u64();
    
    /* Comparison */
    test_cmp_equal();
    test_cmp_less();
    test_cmp_greater();
    test_cmp_upper_bits();
    
    /* Addition */
    test_add_simple();
    test_add_carry();
    test_add_overflow();
    
    /* Subtraction */
    test_sub_simple();
    test_sub_borrow();
    test_sub_underflow();
    
    /* Serialization */
    test_serialize_roundtrip();
    test_serialize_little_endian();
    
    /* Multiplication and Division */
    test_mul_u64();
    test_div_u64();
    
    /* Summary */
    printf("\n===================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return (tests_passed == tests_run) ? 0 : 1;
}

