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

/*
 * Multiply a vector a[] by a scalar b. Add the result into vector t[],
 * starting at the given offset.
 */
void static inline addmul32(uint32_t* t, size_t offset, const uint32_t *a, uint32_t b, size_t t_words, size_t a_words)
{
    uint32_t carry;
    size_t i;
#if defined(USE_SSE2)
    __m128i r0, r1;
#endif

    assert(t_words >= a_words);

    carry = 0;
    i = 0;

    if (a_words == 0) {
        return;
    }

#if defined(USE_SSE2)
    r0 = _mm_set1_epi32((int)b);             // { b, b, b, b }
    r1 = _mm_cvtsi32_si128((int)carry);      // { 0, 0, 0, carry }

    for (i=0; i<(a_words ^ (a_words & 1U)); i+=2) {
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
        r17 = _mm_shuffle_epi32(r16,
                _MM_SHUFFLE(2,0,1,3));  // { new t[i+1], new t[i], *, new carry }
        _mm_storeh_pd((double*)&t[i+offset],
                      _mm_castsi128_pd(r17)); // Store upper 64 bit word (also t[i+1])
        r1 = _mm_castps_si128(_mm_move_ss(
                _mm_castsi128_ps(r1),
                _mm_castsi128_ps(r17)
                ));
    }
    carry = (uint32_t)_mm_cvtsi128_si32(r1);
#endif

    for (; i<a_words; i++) {
        uint64_t prod;
        uint32_t prodl, prodh;

        prod = (uint64_t)a[i]*b;
        prodl = (uint32_t)prod;
        prodh = (uint32_t)(prod >> 32);

        prodl += carry; prodh += prodl < carry;
        t[i+offset] += prodl; prodh += t[i+offset] < prodl;
        carry = prodh;
    }

    for (;i+offset<t_words; i++) {
        t[i+offset] += carry;
        carry = t[i+offset] < carry;
    }

    assert(carry == 0);
}

/*
 * Multiply a vector a[] by a scalar b = b0 + b1*2⁶⁴.
 * Add the result into vector t[],
 *
 * t[] and a[] are little-endian.
 * Return the number of 64-bit words that we wrote into t[]
 */
void inline addmul128(uint64_t *t, const uint64_t *a, uint64_t b0, uint64_t b1, size_t t_words, size_t a_words)
{
    uint32_t b0l, b0h, b1l, b1h;
    uint32_t *t32, *a32;
    size_t i;

    assert(t_words >= a_words + 2);

    if (a_words == 0) {
        return;
    }

    b0l = (uint32_t)b0;
    b0h = (uint32_t)(b0 >> 32);
    b1l = (uint32_t)b1;
    b1h = (uint32_t)(b1 >> 32);

    t32 = (uint32_t*)calloc(t_words*2, sizeof(uint32_t));
    a32 = (uint32_t*)calloc(a_words*2, sizeof(uint32_t));

    for (i=0; i<t_words; i++) {
        t32[2*i] = (uint32_t)t[i];
        t32[2*i+1] = (uint32_t)(t[i] >> 32);
    }
    for (i=0; i<a_words; i++) {
        a32[2*i] = (uint32_t)a[i];
        a32[2*i+1] = (uint32_t)(a[i] >> 32);
    }

    addmul32(t32, 0, a32, b0l, 2*t_words, 2*a_words);
    addmul32(t32, 1, a32, b0h, 2*t_words, 2*a_words);
    addmul32(t32, 2, a32, b1l, 2*t_words, 2*a_words);
    addmul32(t32, 3, a32, b1h, 2*t_words, 2*a_words);

    for (i=0; i<t_words; i++) {
        t[i] = (uint64_t)t32[2*i] + ((uint64_t)t32[2*i+1] << 32);
    }

    free(t32);
    free(a32);
}

/*
 * Square a vector a[] and store the result in t[].
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

            prod = (uint64_t)a[j]*a[i];
            suml = (uint32_t)prod;
            sumh = (uint32_t)(prod >> 32);

            suml += carry;
            sumh += suml < carry;

            t[i+j] += suml;
            carry = sumh + (t[i+j] < suml);
        }

        /** Propagate carry **/
        for (j=i+words; carry>0; j++) {
            t[j] += carry;
            carry = t[j] < carry;
        }
    }

    /** Double mix-products and add squares **/
    carry = 0;
    for (i=0, j=0; i<words; i++, j+=2) {
        uint64_t prod;
        uint32_t suml, sumh, tmp, tmp2;

        prod = (uint64_t)a[i]*a[i];
        suml = (uint32_t)prod;
        sumh = (uint32_t)(prod >> 32);

        suml += carry;
        sumh += suml < carry;

        sumh += (tmp = ((t[j+1] << 1) + (t[j] >> 31)));
        carry = (t[j+1] >> 31) + (sumh < tmp);

        suml += (tmp = (t[j] << 1));
        sumh += (tmp2 = (suml < tmp));
        carry += sumh < tmp2;

        t[j] = suml;
        t[j+1] = sumh;
    }
    assert(carry == 0);

    return 2*words;
}

size_t inline square_w(uint64_t *t, const uint64_t *a, size_t words)
{
    uint32_t *t32, *a32;
    size_t i, res;

    t32 = (uint32_t*)calloc(4*words, sizeof(uint32_t));
    a32 = (uint32_t*)calloc(2*words, sizeof(uint32_t));

    for (i=0; i<words; i++) {
        a32[2*i] = (uint32_t)a[i];
        a32[2*i+1] = (uint32_t)(a[i] >> 32);
    }

    res = square_w_32(t32, a32, words*2)/2;

    for (i=0; i<2*words; i++) {
        t[i] = (uint64_t)t32[2*i] + ((uint64_t)t32[2*i+1] << 32);
    }

    free(t32);
    free(a32);
    return res;
}
