#ifndef __BIGNUM_C
#define __BIGNUM_C

#include "common.h"

#if defined(USE_SSE2)
#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#endif

/*
 * Subtract a multi-word integer b from a.
 *
 * @param out   The location where the multi-word result is stored
 * @param a     Number to subtract from
 * @param b     Number to subtract
 * @param nw    The number of words of both a and b
 * @result      0 if there is no borrow, 1 otherwise
 */
STATIC unsigned sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw)
{
    size_t i;
    unsigned borrow1 , borrow2;

    borrow2 = 0;
    for (i=0; i<nw; i++) {
        borrow1 = b[i] > a[i];
        out[i] = a[i] - b[i];

        borrow1 |= borrow2 > out[i];
        out[i] -= borrow2;

        borrow2 = borrow1;
    }

    return borrow2;
}

/*
 * Select a number out of two, in constant time.
 *
 * @param out   The location where the multi-word result is stored
 * @param a     The first choice, selected if cond is true (non-zero)
 * @param b     The second choice, selected if cond is false (zero)
 * @param cond  The flag that drives the selection
 * @param words The number of words of a, b, and out
 * @return      0 for success, the appropriate code otherwise.
 */
STATIC int mod_select(uint64_t *out, const uint64_t *a, const uint64_t *b, unsigned cond, size_t words)
{
    uint64_t mask;
#if defined(USE_SSE2)
    unsigned pairs, i;
    __m128i r0, r1, r2, r3, r4, r5;

    pairs = (unsigned)words / 2;
    mask = (uint64_t)((cond != 0) - 1); /* 0 for a, 1s for b */

#if SYS_BITS == 64
    r0 = _mm_set1_epi64x((int64_t)mask);
#else
    r0 = _mm_loadl_epi64((__m128i*)&mask);
    r0 = _mm_unpacklo_epi64(r0, r0);
#endif
    for (i=0; i<pairs; i++, a+=2, b+=2, out+=2) {
        r1 = _mm_loadu_si128((__m128i const*)b);
        r2 = _mm_loadu_si128((__m128i const*)a);
        r3 = _mm_and_si128(r0, r1);
        r4 = _mm_andnot_si128(r0, r2);
        r5 = _mm_or_si128(r3, r4);
        _mm_storeu_si128((__m128i*)out, r5);
    }

    if (words & 1) {
        *out = (*b & mask) ^ (*a & ~mask);
    }
#else
    unsigned i;

    mask = (uint64_t)((cond != 0) - 1);
    for (i=0; i<words; i++) {
        *out++ = (*b++ & mask) ^ (*a++ & ~mask);
    }
#endif

    return 0;
}

#endif  /* __BIGNUM_C **/
