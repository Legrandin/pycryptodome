/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Natural numbers (0, 1, 2, ...) of arbitrary but fixed size,
 * with constant-time operations.
 *
 * A Nat holds nw 64-bit words (limbs), least significant first.
 * The number of words is public: no function looks at the value
 * to decide how much work to do, or which memory to access.
 *
 * Unless stated otherwise, operations are truncating:
 * the result is reduced modulo 2^(64*out->nw).
 * The caller (Crypto.Math._IntegerNat) picks the size of out
 * so that no information is lost.
 *
 * Unless stated otherwise, out must not be the same object as
 * any of the inputs.
 */

#ifndef NAT_H
#define NAT_H

#include "common.h"
#include "errors.h"

/* The largest number of words allowed in a Nat (2^20 bits) */
#define NAT_MAX_WORDS ((size_t)1 << 14)

typedef struct {
    size_t nw;
    uint64_t *w;
} Nat;

/** Memory **/
EXPORT_SYM int nat_new(Nat **out, size_t nw);
EXPORT_SYM void nat_free(Nat *x);
EXPORT_SYM int nat_copy(Nat *out, const Nat *a);

/** Conversions **/
EXPORT_SYM int nat_from_bytes(Nat *out, const uint8_t *in, size_t len, int little_endian);
EXPORT_SYM int nat_to_bytes(uint8_t *out, size_t len, const Nat *a, int little_endian);
EXPORT_SYM int nat_from_uint64(Nat *out, uint64_t v);
EXPORT_SYM int nat_bit_length(const Nat *a);

/** Predicates and comparison **/
EXPORT_SYM int nat_is_zero(const Nat *a);
EXPORT_SYM int nat_is_odd(const Nat *a);
EXPORT_SYM int nat_cmp(const Nat *a, const Nat *b);
EXPORT_SYM int nat_get_bit(const Nat *a, size_t n);

/** Arithmetic **/
EXPORT_SYM int nat_add(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_sub(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_mul(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_muladd(Nat *out, const Nat *c, const Nat *a, const Nat *b);
EXPORT_SYM int nat_and(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_or(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_shl(Nat *out, const Nat *a, size_t k);
EXPORT_SYM int nat_shr(Nat *out, const Nat *a, size_t k);

/** Division **/
EXPORT_SYM int nat_divmod(Nat *q, Nat *r, const Nat *a, const Nat *b);
EXPORT_SYM int nat_mod_small(Nat *out, const Nat *a, uint64_t d);

/** Modular arithmetic **/
EXPORT_SYM int nat_mulmod(Nat *out, const Nat *a, const Nat *b, const Nat *m);
EXPORT_SYM int nat_submod(Nat *out, const Nat *a, const Nat *b, const Nat *m);
EXPORT_SYM int nat_powmod(Nat *out, const Nat *a, const Nat *e, const Nat *m);
EXPORT_SYM int nat_invmod(Nat *out, const Nat *a, const Nat *m);

/** Number theory **/
EXPORT_SYM int nat_gcd(Nat *out, const Nat *a, const Nat *b);
EXPORT_SYM int nat_jacobi(Nat *out, const Nat *a, const Nat *n, int negate);
EXPORT_SYM int nat_isqrt(Nat *out, const Nat *a);
EXPORT_SYM int nat_miller_rabin(Nat *out, const Nat *n, const Nat *base);
EXPORT_SYM int nat_lucas(Nat *out, const Nat *n, uint64_t abs_d, int negative_d);

/*
 * Internal functions, shared by the nat*.c files.
 * They work on arrays of words, with the sizes given explicitly.
 */

/** Allocate nw words, initialized to zero (NULL on error) **/
uint64_t *nat_words_alloc(size_t nw);
/** Wipe and free nw words **/
void nat_words_free(uint64_t *w, size_t nw);
/** Allocate a Nat (NULL on error); free it with nat_free() **/
Nat *nat_alloc(size_t nw);

/** Word i of a, or 0 if i is beyond its size **/
static inline uint64_t nat_word(const Nat *a, size_t i)
{
    return i < a->nw ? a->w[i] : 0;
}

/** 1 if the nw words of x are all zero **/
uint64_t words_is_zero(const uint64_t *x, size_t nw);
/** 1 if x == y (nw words each) **/
uint64_t words_eq(const uint64_t *x, const uint64_t *y, size_t nw);
/** 1 if x < y (nw words each) **/
uint64_t words_lt(const uint64_t *x, const uint64_t *y, size_t nw);
/** out = x if mask is all ones, y if it is zero (nw words; out may alias) **/
void words_select(uint64_t *out, uint64_t mask, const uint64_t *x, const uint64_t *y, size_t nw);
/** Swap x and y if mask is all ones (nw words) **/
void words_cswap(uint64_t mask, uint64_t *x, uint64_t *y, size_t nw);
/** out = a + b, return carry (nw words; out may alias) **/
uint64_t words_add(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw);
/** out = a - b, return borrow (nw words; out may alias) **/
uint64_t words_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw);
/** x = x - (y & mask), return borrow (nw words) **/
uint64_t words_cond_sub(uint64_t mask, uint64_t *x, const uint64_t *y, size_t nw);
/** x = x + (y & mask), return carry (nw words) **/
uint64_t words_cond_add(uint64_t mask, uint64_t *x, const uint64_t *y, size_t nw);
/** x = (x >> 1) | (top << 63 of the last word) (nw words) **/
void words_shr1(uint64_t *x, uint64_t top, size_t nw);
/** Shift x right by k bits; k is secret, at most 64*nw. tmp has nw words. **/
void words_shr_secret(uint64_t *x, uint64_t k, uint64_t *tmp, size_t nw);
/** Shift x left by k bits; k is secret, at most 64*nw. tmp has nw words. **/
void words_shl_secret(uint64_t *x, uint64_t k, uint64_t *tmp, size_t nw);
/** Number of trailing zero bits in x (64*nw if x is zero) **/
uint64_t words_ctz(const uint64_t *x, size_t nw);

/** Remainder of a divided by b (r has b->nw words); b must not be 0 **/
int nat_divmod_words(uint64_t *q, size_t q_nw, uint64_t *r, const Nat *a, const Nat *b);

/*
 * Montgomery arithmetic, for an odd modulus.
 * Numbers in Montgomery form only exist inside a single call
 * to a nat_* function.
 */
typedef struct {
    size_t nw;
    uint64_t *n;        /* the modulus */
    uint64_t m0;        /* -n^{-1} mod 2^64 */
    uint64_t *r2;       /* R^2 mod n */
    uint64_t *one;      /* R mod n (1 in Montgomery form) */
    uint64_t *unit;     /* the number 1 (not in Montgomery form) */
    uint64_t *tmp;      /* scratchpad, nw+2 words */
} MontCtx;

int mont_ctx_new(MontCtx **out, const Nat *n);
void mont_ctx_free(MontCtx *ctx);
/** out = a*b/R mod n; a, b < n; out may alias a or b **/
void mont_mul(uint64_t *out, const uint64_t *a, const uint64_t *b, MontCtx *ctx);
/** out = x*R mod n, for x < n **/
void mont_to(uint64_t *out, const uint64_t *x, MontCtx *ctx);
/** out = x/R mod n **/
void mont_from(uint64_t *out, const uint64_t *x, MontCtx *ctx);
/** out = (a + b) mod n, a, b < n; out may alias **/
void mod_add(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t nw);
/** out = (a - b) mod n, a, b < n; out may alias **/
void mod_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t nw);
/** x = x/2 mod n, x < n, n odd **/
void mod_half(uint64_t *x, const uint64_t *n, size_t nw);
/** out = base^e in Montgomery form; base_m is in Montgomery form **/
int mont_pow(uint64_t *out, const uint64_t *base_m, const Nat *e, MontCtx *ctx);

/** out = a^{-1} mod n, for n odd and a < n (nw words); ERR_VALUE if there is no inverse **/
int inv_odd(uint64_t *out, const uint64_t *a, const uint64_t *n, size_t nw);

#endif
