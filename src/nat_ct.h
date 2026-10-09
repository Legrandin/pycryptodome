/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time helpers on 64-bit words.
 *
 * A "bit" is a uint64_t equal to 0 or 1.
 * A "mask" is a uint64_t equal to 0 or to all ones.
 *
 * None of these functions contain branches, and they do not use
 * comparison operators on their arguments, so that the compiler has
 * no reason to emit conditional jumps.
 */

#ifndef NAT_CT_H
#define NAT_CT_H

#include "common.h"
#include "multiply.h"

#if defined(NAT_CTGRIND)
#include <valgrind/memcheck.h>
#endif

/*
 * Hide the value of x from the optimizer, so that it cannot turn
 * a computation with masks back into a branch.
 */
static inline uint64_t ct_barrier(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ ("" : "+r" (x));
    return x;
#else
    volatile uint64_t y = x;
    return y;
#endif
}

/**
 * Make a secret-dependent value public on purpose, for example the fact
 * that an operation failed. Every intended leak goes through here.
 *
 * In a build with NAT_CTGRIND, secret inputs are marked as undefined
 * memory, so that Valgrind reports any branch or memory access that
 * depends on them; this function marks the value as defined again.
 */
static inline uint64_t ct_declassify(uint64_t x)
{
#if defined(NAT_CTGRIND)
    VALGRIND_MAKE_MEM_DEFINED(&x, sizeof x);
#endif
    return x;
}

/** 1 if x is not zero, 0 otherwise **/
static inline uint64_t ct_nz(uint64_t x)
{
    return (x | (0 - x)) >> 63;
}

/** 1 if x is zero, 0 otherwise **/
static inline uint64_t ct_z(uint64_t x)
{
    return 1 ^ ct_nz(x);
}

/** 1 if x == y, 0 otherwise **/
static inline uint64_t ct_eq(uint64_t x, uint64_t y)
{
    return ct_z(x ^ y);
}

/** 1 if x < y, 0 otherwise (the borrow of x - y) **/
static inline uint64_t ct_lt(uint64_t x, uint64_t y)
{
    uint64_t d = x - y;
    return ((~x & y) | (~(x ^ y) & d)) >> 63;
}

/** Turn a bit into a mask **/
static inline uint64_t ct_mask(uint64_t bit)
{
    return 0 - ct_barrier(bit);
}

/** x if mask is all ones, y if mask is zero **/
static inline uint64_t ct_select(uint64_t mask, uint64_t x, uint64_t y)
{
    return y ^ (mask & (x ^ y));
}

#if defined(HAVE_UINT128)

/*
 * With a 128-bit type, the compiler uses the carry flag (add/adc, sub/sbb),
 * which is both faster and constant time.
 */

/** a + b + carry_in, with the carry out (0 or 1) in *carry_out **/
static inline uint64_t ct_add(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t *carry_out)
{
    __uint128_t s = (__uint128_t)a + b + carry_in;

    *carry_out = (uint64_t)(s >> 64);
    return (uint64_t)s;
}

/** a - b - borrow_in, with the borrow out (0 or 1) in *borrow_out **/
static inline uint64_t ct_sub(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t *borrow_out)
{
    __uint128_t d = (__uint128_t)a - b - borrow_in;

    *borrow_out = (uint64_t)(d >> 64) & 1;
    return (uint64_t)d;
}

/**
 * Compute a*b + c + d, which always fits into 128 bits.
 * Return the lower 64 bits, and store the higher 64 bits into *hi.
 */
static inline uint64_t ct_mac(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t *hi)
{
    __uint128_t t = (__uint128_t)a * b + c + d;

    *hi = (uint64_t)(t >> 64);
    return (uint64_t)t;
}

#else

/** a + b + carry_in, with the carry out (0 or 1) in *carry_out **/
static inline uint64_t ct_add(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t *carry_out)
{
    uint64_t s1, s2, c1, c2;

    s1 = a + b;
    c1 = ((a & b) | ((a | b) & ~s1)) >> 63;
    s2 = s1 + carry_in;
    c2 = ((s1 & carry_in) | ((s1 | carry_in) & ~s2)) >> 63;
    *carry_out = c1 | c2;
    return s2;
}

/** a - b - borrow_in, with the borrow out (0 or 1) in *borrow_out **/
static inline uint64_t ct_sub(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t *borrow_out)
{
    uint64_t d1, d2, b1, b2;

    d1 = a - b;
    b1 = ((~a & b) | (~(a ^ b) & d1)) >> 63;
    d2 = d1 - borrow_in;
    b2 = ((~d1 & borrow_in) | (~(d1 ^ borrow_in) & d2)) >> 63;
    *borrow_out = b1 | b2;
    return d2;
}

/**
 * Compute a*b + c + d, which always fits into 128 bits.
 * Return the lower 64 bits, and store the higher 64 bits into *hi.
 */
static inline uint64_t ct_mac(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t *hi)
{
    uint64_t lo, h, carry;

    DP_MULT(a, b, lo, h);
    lo = ct_add(lo, c, 0, &carry);
    h += carry;
    lo = ct_add(lo, d, 0, &carry);
    h += carry;
    *hi = h;
    return lo;
}

#endif /* HAVE_UINT128 */

/** Number of significant bits in x (0 for x == 0) **/
static inline uint64_t ct_bitlen64(uint64_t x)
{
    uint64_t n = 0;
    unsigned s;

    for (s=32; s>0; s>>=1) {
        uint64_t t, m;

        t = x >> s;
        m = ct_mask(ct_nz(t));
        n += s & m;
        x = ct_select(m, t, x);
    }
    return n + x;
}

/** Number of trailing zero bits in x (64 for x == 0) **/
static inline uint64_t ct_ctz64(uint64_t x)
{
    uint64_t lowest;

    lowest = x & (0 - x);
    return ct_select(ct_mask(ct_z(x)), 64, ct_bitlen64(lowest) - 1);
}

#endif
