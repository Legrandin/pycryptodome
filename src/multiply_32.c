#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "multiply.h"

int static inline addmul32(uint32_t* t, const uint32_t *a, uint32_t b, size_t words)
{
    uint32_t carry;
    int i;
#if defined(USE_SSE2)
    __m128i r0, r1;
#endif

    if (words == 0) {
        return 0;
    }

    carry = 0;
    i = 0;

#if defined(USE_SSE2)
    
    // NOTE: we assume a[] is 64-bit aligned
   
    r0 = _mm_set1_epi32(b);             // { b, b, b, b }
    r1 = _mm_cvtsi32_si128(carry);      // { 0, 0, 0, carry }
    
    for (i=0; i<(words & ~1); i+=2) {
        __m128i r10, r11, r12, r13, r14, r15, r16, r17;
       
        r10 = _mm_shuffle_epi32(
                _mm_castpd_si128(
                    _mm_set_sd(*(double*)&a[i])
                ),
             _MM_SHUFFLE(2,1,2,0));     // { 0, a[i+1], 0, a[i] }
        r11 = _mm_mul_epu32(r0,  r10);  // { a[i+1]*b,  a[i]*b  }
        r12 = _mm_shuffle_epi32(
                _mm_castpd_si128(
                    _mm_set_sd(*(double*)&t[i])
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
        
        _mm_storeh_pd((double*)&t[i],
                      _mm_castsi128_pd(r17)); // Store upper 64 bit word (also t[i+1])
        
        r1 = _mm_castps_si128(_mm_move_ss(
                _mm_castsi128_ps(r1),
                _mm_castsi128_ps(r17)
                ));
    }
    carry = _mm_cvtsi128_si32(r1);
#endif
    
    for (; i<words; i++) {
        uint64_t prod;
        uint32_t prodl, prodh;

        prod = (uint64_t)a[i]*b;
        prodl = (uint32_t)prod;
        prodh = (uint32_t)(prod >> 32);

        prodl += carry; prodh += prodl < carry;
        t[i] += prodl; prodh += t[i] < prodl;
        carry = prodh;
    }

    for (;carry; i++) {
        t[i] += carry; carry = t[i] < carry;
    }

    return i;
}


uint64_t addmul128(uint64_t * RESTRICT t, const uint64_t * RESTRICT a, uint64_t b0, uint64_t b1, size_t words)
{
    int res;
    uint32_t b0l, b0h, b1l, b1h;

    if (words == 0) {
        return 0;
    }

    b0l = (uint32_t)b0;
    b0h = (uint32_t)(b0 >> 32);
    b1l = (uint32_t)b1;
    b1h = (uint32_t)(b1 >> 32);

    // TODO: make it work for BE too

    addmul32((uint32_t*)t+0, (uint32_t*)a, b0l, 2*words);
    addmul32((uint32_t*)t+1, (uint32_t*)a, b0h, 2*words);
    addmul32((uint32_t*)t+2, (uint32_t*)a, b1l, 2*words);
    res = addmul32((uint32_t*)t+3, (uint32_t*)a, b1h, 2*words) + 3;

    return (res+1)/2;
}

size_t square_w_32(uint32_t *t, const uint32_t *a, size_t words)
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

size_t square_w(uint64_t *t, const uint64_t *a, size_t words)
{
    // TODO: make it work for BE too
    return square_w_32((uint32_t*)t, (const uint32_t*)a, words*2)/2;
}
