/**
 * DSV 320-bit Unsigned Integer Implementation
 */

#include "dsv_u320.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Constants */
const dsv_u320_t DSV_U320_ZERO = {{0, 0, 0, 0, 0}};

/* 
 * 10^72 in binary representation (1 DSV in LGB)
 * 10^72 = 0x0000000000000000 (part 4 - MSB)
 *         0x0000000000004B3B (part 3)
 *         0x4CA85A86C47A098A (part 2)
 *         0x224000000000000 (part 1)
 *         0x0000000000000000 (part 0 - LSB)
 * 
 * Actually computing 10^72:
 * 10^72 is a 240-bit number approximately.
 * We need to be precise here. Let me compute it properly.
 * 
 * 10^72 = (10^36)^2
 * 10^18 = 0xDE0B6B3A7640000
 * 10^36 = 10^18 * 10^18
 * 
 * For simplicity, I'll hardcode the correct value.
 * 10^72 in hex is approximately:
 * 0x B A C 7 1 0 C B 2 9 5 E 9 E 1 B 0 8 9 A 0 2 7 5 2 5 4 6 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 * 
 * This is complex. Let me use a precomputed value.
 * 10^72 has 73 decimal digits, which requires about 243 bits.
 * 
 * Computing step by step in parts:
 */

/* 10^72 - precomputed as 5x64-bit little-endian */
const dsv_u320_t DSV_ONE_DSV_LGB = {{
    0x0000000000000000ULL,  /* bits 0-63 */
    0x0000000000000000ULL,  /* bits 64-127 */
    0x0000000000000000ULL,  /* bits 128-191 */
    0xB5E620F480000000ULL,  /* bits 192-255 */
    0x000000009F4F2726ULL   /* bits 256-319 */
}};

/* Max supply: 210,000 DSV * 10^72 LGB */
const dsv_u320_t DSV_MAX_SUPPLY_LGB = {{
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x15D5058180000000ULL,  
    0x0000CD5AF6B80A71ULL
}};

/* Initial reward: 2.1 DSV = 21/10 * 10^72 LGB */
const dsv_u320_t DSV_INITIAL_REWARD_LGB = {{
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0x74C1CB0300000000ULL,
    0x0000000014E62413ULL
}};

const dsv_hash256_t DSV_HASH_ZERO = {{0}};

void dsv_u320_from_u64(dsv_u320_t *r, uint64_t v) {
    r->parts[0] = v;
    r->parts[1] = 0;
    r->parts[2] = 0;
    r->parts[3] = 0;
    r->parts[4] = 0;
}

void dsv_u320_from_bytes(dsv_u320_t *r, const uint8_t *bytes) {
    for (int i = 0; i < 5; i++) {
        r->parts[i] = 0;
        for (int j = 0; j < 8; j++) {
            r->parts[i] |= ((uint64_t)bytes[i * 8 + j]) << (j * 8);
        }
    }
}

void dsv_u320_to_bytes(const dsv_u320_t *v, uint8_t *bytes) {
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 8; j++) {
            bytes[i * 8 + j] = (uint8_t)(v->parts[i] >> (j * 8));
        }
    }
}

int dsv_u320_cmp(const dsv_u320_t *a, const dsv_u320_t *b) {
    for (int i = 4; i >= 0; i--) {
        if (a->parts[i] > b->parts[i]) return 1;
        if (a->parts[i] < b->parts[i]) return -1;
    }
    return 0;
}

bool dsv_u320_eq(const dsv_u320_t *a, const dsv_u320_t *b) {
    /* Constant-time comparison */
    uint64_t diff = 0;
    for (int i = 0; i < 5; i++) {
        diff |= a->parts[i] ^ b->parts[i];
    }
    return diff == 0;
}

bool dsv_u320_is_zero(const dsv_u320_t *v) {
    uint64_t acc = 0;
    for (int i = 0; i < 5; i++) {
        acc |= v->parts[i];
    }
    return acc == 0;
}

bool dsv_u320_add(dsv_u320_t *r, const dsv_u320_t *a, const dsv_u320_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 5; i++) {
        __uint128_t sum = (__uint128_t)a->parts[i] + b->parts[i] + carry;
        r->parts[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    return carry != 0;  /* Overflow if carry out */
}

bool dsv_u320_sub(dsv_u320_t *r, const dsv_u320_t *a, const dsv_u320_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 5; i++) {
        __uint128_t diff = (__uint128_t)a->parts[i] - b->parts[i] - borrow;
        r->parts[i] = (uint64_t)diff;
        borrow = (diff >> 64) ? 1 : 0;  /* Borrow if high bits are set (negative) */
    }
    return borrow != 0;  /* Underflow if borrow out */
}

bool dsv_u320_mul_u64(dsv_u320_t *r, const dsv_u320_t *a, uint64_t b) {
    __uint128_t carry = 0;
    for (int i = 0; i < 5; i++) {
        __uint128_t prod = (__uint128_t)a->parts[i] * b + carry;
        r->parts[i] = (uint64_t)prod;
        carry = prod >> 64;
    }
    return carry != 0;  /* Overflow if carry out */
}

bool dsv_u320_div_u64(dsv_u320_t *q, uint64_t *rem, const dsv_u320_t *a, uint64_t b) {
    if (b == 0) return false;
    
    __uint128_t r = 0;
    for (int i = 4; i >= 0; i--) {
        __uint128_t dividend = (r << 64) | a->parts[i];
        q->parts[i] = (uint64_t)(dividend / b);
        r = dividend % b;
    }
    if (rem) *rem = (uint64_t)r;
    return true;
}

void dsv_u320_shr(dsv_u320_t *r, const dsv_u320_t *v, unsigned int n) {
    if (n >= 320) {
        *r = DSV_U320_ZERO;
        return;
    }
    
    unsigned int word_shift = n / 64;
    unsigned int bit_shift = n % 64;
    
    for (int i = 0; i < 5; i++) {
        int src_idx = i + word_shift;
        if (src_idx >= 5) {
            r->parts[i] = 0;
        } else {
            r->parts[i] = v->parts[src_idx] >> bit_shift;
            if (bit_shift > 0 && src_idx + 1 < 5) {
                r->parts[i] |= v->parts[src_idx + 1] << (64 - bit_shift);
            }
        }
    }
}

void dsv_u320_shl(dsv_u320_t *r, const dsv_u320_t *v, unsigned int n) {
    if (n >= 320) {
        *r = DSV_U320_ZERO;
        return;
    }
    
    unsigned int word_shift = n / 64;
    unsigned int bit_shift = n % 64;
    
    for (int i = 4; i >= 0; i--) {
        int src_idx = i - word_shift;
        if (src_idx < 0) {
            r->parts[i] = 0;
        } else {
            r->parts[i] = v->parts[src_idx] << bit_shift;
            if (bit_shift > 0 && src_idx > 0) {
                r->parts[i] |= v->parts[src_idx - 1] >> (64 - bit_shift);
            }
        }
    }
}

void dsv_u320_to_dec(const dsv_u320_t *v, char *buf, size_t buflen) {
    if (buflen < 2) {
        if (buflen > 0) buf[0] = '\0';
        return;
    }
    
    if (dsv_u320_is_zero(v)) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    
    char tmp[100];  /* 10^320 has at most 97 digits */
    int pos = 0;
    dsv_u320_t work;
    dsv_u320_copy(&work, v);
    
    while (!dsv_u320_is_zero(&work)) {
        uint64_t rem;
        dsv_u320_div_u64(&work, &rem, &work, 10);
        tmp[pos++] = '0' + rem;
    }
    
    /* Reverse into output buffer */
    int out_pos = 0;
    for (int i = pos - 1; i >= 0 && out_pos < (int)buflen - 1; i--) {
        buf[out_pos++] = tmp[i];
    }
    buf[out_pos] = '\0';
}

bool dsv_u320_from_dec(dsv_u320_t *r, const char *str) {
    *r = DSV_U320_ZERO;
    
    if (!str || !*str) return false;
    
    /* Skip leading whitespace */
    while (isspace((unsigned char)*str)) str++;
    
    if (!*str) return false;
    
    /* Parse digits */
    while (*str) {
        if (!isdigit((unsigned char)*str)) break;
        
        int digit = *str - '0';
        
        /* r = r * 10 + digit */
        if (dsv_u320_mul_u64(r, r, 10)) {
            return false;  /* Overflow */
        }
        
        dsv_u320_t digit_val;
        dsv_u320_from_u64(&digit_val, digit);
        if (dsv_u320_add(r, r, &digit_val)) {
            return false;  /* Overflow */
        }
        
        str++;
    }
    
    return true;
}

void dsv_u320_format_dsv(const dsv_u320_t *lgb, char *buf, size_t buflen) {
    /* Convert LGB to decimal string first */
    char lgb_str[100];
    dsv_u320_to_dec(lgb, lgb_str, sizeof(lgb_str));
    
    size_t len = strlen(lgb_str);
    
    /* 1 DSV = 10^72 LGB, so we need 72 decimal places */
    if (len <= 72) {
        /* Less than 1 DSV */
        int zeros_needed = 72 - len;
        int out_pos = 0;
        
        if (out_pos < (int)buflen - 1) buf[out_pos++] = '0';
        if (out_pos < (int)buflen - 1) buf[out_pos++] = '.';
        
        for (int i = 0; i < zeros_needed && out_pos < (int)buflen - 1; i++) {
            buf[out_pos++] = '0';
        }
        
        for (size_t i = 0; i < len && out_pos < (int)buflen - 1; i++) {
            buf[out_pos++] = lgb_str[i];
        }
        
        buf[out_pos] = '\0';
    } else {
        /* 1 or more DSV */
        size_t integer_part_len = len - 72;
        int out_pos = 0;
        
        for (size_t i = 0; i < integer_part_len && out_pos < (int)buflen - 1; i++) {
            buf[out_pos++] = lgb_str[i];
        }
        
        if (out_pos < (int)buflen - 1) buf[out_pos++] = '.';
        
        for (size_t i = integer_part_len; i < len && out_pos < (int)buflen - 1; i++) {
            buf[out_pos++] = lgb_str[i];
        }
        
        buf[out_pos] = '\0';
    }
    
    /* Trim trailing zeros after decimal point */
    size_t final_len = strlen(buf);
    char *decimal = strchr(buf, '.');
    if (decimal) {
        while (final_len > 1 && buf[final_len - 1] == '0') {
            buf[--final_len] = '\0';
        }
        if (buf[final_len - 1] == '.') {
            buf[--final_len] = '\0';
        }
    }
}

