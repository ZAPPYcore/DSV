/**
 * DSV 320-bit Unsigned Integer Arithmetic
 * 
 * All operations are constant-time where security-relevant.
 */

#ifndef DSV_U320_H
#define DSV_U320_H

#include "dsv_types.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize from uint64 */
void dsv_u320_from_u64(dsv_u320_t *r, uint64_t v);

/* Initialize from byte array (little-endian, 40 bytes) */
void dsv_u320_from_bytes(dsv_u320_t *r, const uint8_t *bytes);

/* Export to byte array (little-endian, 40 bytes) */
void dsv_u320_to_bytes(const dsv_u320_t *v, uint8_t *bytes);

/* Compare: returns -1 if a<b, 0 if a==b, 1 if a>b */
int dsv_u320_cmp(const dsv_u320_t *a, const dsv_u320_t *b);

/* Constant-time compare for equality */
bool dsv_u320_eq(const dsv_u320_t *a, const dsv_u320_t *b);

/* Check if zero */
bool dsv_u320_is_zero(const dsv_u320_t *v);

/* Addition: r = a + b, returns true if overflow */
bool dsv_u320_add(dsv_u320_t *r, const dsv_u320_t *a, const dsv_u320_t *b);

/* Subtraction: r = a - b, returns true if underflow */
bool dsv_u320_sub(dsv_u320_t *r, const dsv_u320_t *a, const dsv_u320_t *b);

/* Multiply by uint64: r = a * b, returns true if overflow */
bool dsv_u320_mul_u64(dsv_u320_t *r, const dsv_u320_t *a, uint64_t b);

/* Divide by uint64: q = a / b, r = a % b, returns false if b==0 */
bool dsv_u320_div_u64(dsv_u320_t *q, uint64_t *r, const dsv_u320_t *a, uint64_t b);

/* Right shift by n bits */
void dsv_u320_shr(dsv_u320_t *r, const dsv_u320_t *v, unsigned int n);

/* Left shift by n bits */
void dsv_u320_shl(dsv_u320_t *r, const dsv_u320_t *v, unsigned int n);

/* Convert to decimal string (caller provides buffer of at least 98 chars) */
void dsv_u320_to_dec(const dsv_u320_t *v, char *buf, size_t buflen);

/* Parse from decimal string */
bool dsv_u320_from_dec(dsv_u320_t *r, const char *str);

/* Format as DSV with proper decimal places (for display) */
void dsv_u320_format_dsv(const dsv_u320_t *lgb, char *buf, size_t buflen);

/* Copy */
static inline void dsv_u320_copy(dsv_u320_t *dst, const dsv_u320_t *src) {
    memcpy(dst, src, sizeof(dsv_u320_t));
}

/* Clear (secure) */
static inline void dsv_u320_clear(dsv_u320_t *v) {
    DSV_SECURE_ZERO(v, sizeof(dsv_u320_t));
}

#ifdef __cplusplus
}
#endif

#endif /* DSV_U320_H */

