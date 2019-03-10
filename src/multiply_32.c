/*
Copyright (c) 2017, Helder Eijs <helderijs@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "multiply.h"

#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#endif

#if defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#endif

#if defined(PYCRYPTO_LITTLE_ENDIAN)
#define INDEX(x, i) ((x) + (i))
#elif defined(PYCRYPTO_BIG_ENDIAN) 
#define INDEX(x, i) (((x) + (i)) ^ 1)
#else
#error Undefined endianness
#endif

/*
 * Multiply a vector a[] by a scalar b. Add the result into vector t[],
 * starting from index offset.
 *
 * t[] and a[] are little-endian but words are interleaved in big-endian systems.
 * In other words, while in little-endian systems they are laid out as:
 *
 *   t[0], t[1], t[2], t[3], ...
 *
 * In a big-endian system they are instead:
 *
 *   t[1], t[0], t[3], t[2], t[5], t[4], ...
 *
 * Returns now many 32-bit words we wrote into t[]
 */
size_t static inline addmul32(uint32_t* t, size_t offset, const uint32_t *a, uint32_t b, size_t words)
{
    uint32_t carry;
    size_t i;
#if defined(USE_SSE2)
    __m128i r0, r1;
#endif

    carry = 0;
    i = 0;

    if (words == 0) {
        return 0;
    }

#if defined(USE_SSE2)

#ifndef PYCRYPTO_LITTLE_ENDIAN
#error SSE2 only designed for little endian systems
#endif
    r0 = _mm_set1_epi32((int)b);             // { b, b, b, b }
    r1 = _mm_cvtsi32_si128((int)carry);      // { 0, 0, 0, carry }

    for (i=0; i<(words ^ (words & 1U)); i+=2) {
        __m128i r10, r11, r12, r13, r14, r15, r16, r17;

        r10 = _mm_shuffle_epi32(
                _mm_castpd_si128(
                    _mm_set_sd(*(double*)&a[i])
                ),
             _MM_SHUFFLE(2,1,2,0));     // { 0, a[i+1], 0, a[i] }

        r11 = _mm_mul_epu32(r0,  r10);  // { a[i+1]*b,  a[i]*b  }

        r12 = _mm_shuffle_epi32(
                _mm_castpd_si128(
                    _mm_set_sd(*(double*)&t[i+offset])
                ),
             _MM_SHUFFLE(2,1,2,0));     // { 0, t[i+1], 0, t[i] }
        r13 = _mm_add_epi64(r12, r1);   // { t[i+1],  t[i]+carry }

        r14 = _mm_add_epi64(r11, r13);  // { a[i+1]*b+t[i+1],  a[i]*b+t[i]+carry }

        r15 = _mm_shuffle_epi32(
                _mm_move_epi64(r14),    // { 0, a[i]*b+t[i]+carry }
                _MM_SHUFFLE(2,1,2,2)
              );                        // { 0, H(a[i]*b+t[i]+carry), 0, 0 }

        r16 = _mm_add_epi64(r14, r15);  // { next_carry, new t[i+1], *, new t[i] }

        r17 = _mm_shuffle_epi32(r16, _MM_SHUFFLE(2,0,1,3));
                                        // { new t[i+1], new t[i], *, new carry }

        _mm_storeh_pd((double*)&t[i+offset],
                      _mm_castsi128_pd(r17)); // Store upper 64 bit word (also t[i+1])

        r1 = _mm_castps_si128(_mm_move_ss(
                _mm_castsi128_ps(r1),
                _mm_castsi128_ps(r17)
                ));
    }
    carry = (uint32_t)_mm_cvtsi128_si32(r1);
#endif

    for (; i<words; i++) {
        uint64_t prod;
        uint32_t prodl, prodh;

        prod = (uint64_t)a[INDEX(i, 0)]*b;
        prodl = (uint32_t)prod;
        prodh = (uint32_t)(prod >> 32);

        prodl += carry; prodh += prodl < carry;
        t[INDEX(i, offset)] += prodl; prodh += t[INDEX(i, offset)] < prodl;
        carry = prodh;
    }

    for (;carry; i++) {
        t[INDEX(i, offset)] += carry; carry = t[INDEX(i, offset)] < carry;
    }

    return i;
}

size_t static inline max_size_t(size_t a, size_t b)
{
    return a>b ? a : b;
}

/*
 * Multiply a vector a[] by a scalar b = b0 + b1*2^64.
 * Add the result into vector t[],
 *
 * t[] and a[] are little-endian.
 * Return the number of 64-bit words that we wrote into t[]
 */
size_t inline addmul128(uint64_t * RESTRICT t, const uint64_t * RESTRICT a, uint64_t b0, uint64_t b1, size_t words)
{
    uint32_t b0l, b0h, b1l, b1h;
    size_t words32, res;

    if (words == 0) {
        return 0;
    }

    b0l = (uint32_t)b0;
    b0h = (uint32_t)(b0 >> 32);
    b1l = (uint32_t)b1;
    b1h = (uint32_t)(b1 >> 32);

    words32 = addmul32((uint32_t*)t, 0, (uint32_t*)a, b0l, 2*words);
    
    res = addmul32((uint32_t*)t, 1, (uint32_t*)a, b0h, 2*words);
    words32 = max_size_t(words32, res + 1);
    
    res = addmul32((uint32_t*)t, 2, (uint32_t*)a, b1l, 2*words);
    words32 = max_size_t(words32, res + 2);
    
    res = addmul32((uint32_t*)t, 3, (uint32_t*)a, b1h, 2*words);
    words32 = max_size_t(words32, res + 3);

    return (words32+1)/2;
}

/*
 * Square a vector a[] and store the result in t[].
 *
 * Words in t[] and a[] are interleaved in big-endian systems.
 * In other words, while in little-endian systems they are laid out as:
 *   
 *   t[0], t[1], t[2], t[3], ...
 *
 * In a big-endian system they are instead:
 *
 *   t[1], t[0], t[3], t[2], t[5], t[4], ...
 *
 */
size_t static inline square_w_32(uint32_t *t, const uint32_t *a, size_t words)
{
    size_t i, j;
    uint32_t carry;

    if (words == 0) {
        return 0;
    }

    memset(t, 0, 2*sizeof(t[0])*words);

    /** Compute all mix-products without doubling **/
    for (i=0; i<words; i++) {
        carry = 0;

        for (j=i+1; j<words; j++) {
            uint64_t prod;
            uint32_t suml, sumh;

            prod = (uint64_t)a[INDEX(j, 0)]*a[INDEX(i, 0)];
            suml = (uint32_t)prod;
            sumh = (uint32_t)(prod >> 32);

            suml += carry;
            sumh += suml < carry;

            t[INDEX(i+j, 0)] += suml;
            carry = sumh + (t[INDEX(i+j, 0)] < suml);
        }

        /** Propagate carry **/
        for (j=i+words; carry>0; j++) {
            t[INDEX(j, 0)] += carry;
            carry = t[INDEX(j, 0)] < carry;
        }
    }

    /** Double mix-products and add squares **/
    carry = 0;
    for (i=0, j=0; i<words; i++, j+=2) {
        uint64_t prod;
        uint32_t suml, sumh, tmp, tmp2;

        prod = (uint64_t)a[INDEX(i, 0)]*a[INDEX(i, 0)];
        suml = (uint32_t)prod;
        sumh = (uint32_t)(prod >> 32);

        suml += carry;
        sumh += suml < carry;

        sumh += (tmp = ((t[INDEX(j+1, 0)] << 1) + (t[INDEX(j, 0)] >> 31)));
        carry = (t[INDEX(j+1, 0)] >> 31) + (sumh < tmp);

        suml += (tmp = (t[INDEX(j, 0)] << 1));
        sumh += (tmp2 = (suml < tmp));
        carry += sumh < tmp2;

        t[INDEX(j, 0)] = suml;
        t[INDEX(j+1, 0)] = sumh;
    }
    assert(carry == 0);

    return 2*words;
}

size_t inline square_w(uint64_t *t, const uint64_t *a, size_t words)
{
    return square_w_32((uint32_t*)t, (const uint32_t*)a, words*2)/2;
}
