#include "../common.h"
#include <x86intrin.h>

__m128i reduce(__m128i prod_high, __m128i prod_low);
void clmult(__m128i *prod_high, __m128i *prod_low, __m128i a, __m128i b);
__m128i multx(__m128i a);
__m128i swap(__m128i a);

void test_reduce_1(void)
{
    uint8_t prod_high[16] = { 0xB7, 0xD5, 0xA2, 0x4C, 0xC4, 0x84, 0xB3, 0x23, 0xA8, 0x70, 0x56, 0x4A, 0xD7, 0xEE, 0x79, 0x01 };
    uint8_t prod_low[16]  = { 0xFB, 0x3A, 0xB9, 0x7E, 0xB2, 0x9E, 0xDF, 0xFC, 0x44, 0xE9, 0xCB, 0x94, 0xD8, 0x83, 0xD2, 0x8F };
    uint8_t out[16];
    uint8_t expected[16]  = { 0xFA, 0x4E, 0x14, 0xF6, 0xBE, 0x8D, 0xCD, 0x17, 0xCD, 0x00, 0xE3, 0x00, 0x12, 0x29, 0x45, 0x2A };
    __m128i r1, r2, r3;
    int result;

    memcpy(&r1, prod_high, 16);
    memcpy(&r2, prod_low, 16);
    r3 = reduce(r1, r2);
    memcpy(out, &r3, 16);
    
    result = memcmp(expected, out, 16);
    assert(result == 0);
}

void test_multx_1(void)
{
    uint8_t zeroes[16] = { 0 };
    uint8_t out[16];
    __m128i r1, r2;
    int result;

    memcpy(&r1, zeroes, 16);
    r2 = multx(r1);
    memcpy(out, &r2, 16);
    
    result = memcmp(zeroes, out, 16);
    assert(result == 0);
}

void test_multx_2(void)
{
    uint8_t in[16];
    uint8_t expected[16];
    uint8_t out[16];
    __m128i r1, r2;
    int result;

    memset(in, 0x55, 16);
    memset(expected, 0xAA, 16);

    memcpy(&r1, in, 16);
    r2 = multx(r1);
    memcpy(out, &r2, 16);
    
    result = memcmp(expected, out, 16);
    assert(result == 0);
}

void test_multx_3(void)
{
    uint8_t in[16] =       { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80 };
    uint8_t expected[16] = { 1, 0, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc2 };
    uint8_t out[16];
    __m128i r1, r2;
    int result;

    memcpy(&r1, in, 16);
    r2 = multx(r1);
    memcpy(out, &r2, 16);
    
    result = memcmp(expected, out, 16);
    assert(result == 0);
}

void test_swap_1(void)
{
    uint8_t in[16] =       { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    uint8_t expected[16] = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    uint8_t out[16];
    __m128i r1, r2;
    int result;

    memcpy(&r1, in, 16);
    r2 = swap(r1);
    memcpy(out, &r2, 16);

    result = memcmp(expected, out, 16);
    assert(result == 0);
}

void test_clmul_1(void)
{
    uint8_t in_a[16] = { 1, 0, 0, 0, 0, 0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t in_b[16] = { 0xFF, 0, 0, 0, 0, 0 ,0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0xFF };
    uint8_t exp_lo[16] = { 0xFF, 0, 0, 0, 0, 0 ,0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0xFF };
    uint8_t exp_hi[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t out_hi[16], out_lo[16];
    __m128i r1, r2, r3, r4;
    int result;

    memcpy(&r1, in_a, 16);
    memcpy(&r2, in_b, 16);
    clmult(&r3, &r4, r1, r2);
    memcpy(out_hi, &r3, 16);
    memcpy(out_lo, &r4, 16);

    result = memcmp(exp_lo, out_lo, 16);
    assert(result == 0);
    
    result = memcmp(exp_hi, out_hi, 16);
    assert(result == 0);
    
    clmult(&r3, &r4, r2, r1);
    memcpy(out_hi, &r3, 16);
    memcpy(out_lo, &r4, 16);
    
    result = memcmp(exp_lo, out_lo, 16);
    assert(result == 0);
    
    result = memcmp(exp_hi, out_hi, 16);
    assert(result == 0);
}

void test_clmul_2(void)
{
    uint8_t in_a[16] = { 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x81 };
    uint8_t in_b[16] = { 0xee, 0x89, 0xf9, 0x4f, 0x98, 0x24, 0xff, 0xff, 0x90, 0x00, 0x90, 0xff, 0x8f, 0x89, 0xff, 0xff };

    uint8_t exp_lo[16] = { 0x84, 0x1c, 0xe5, 0xb3, 0x1c, 0x3e, 0x59, 0xf8, 0x92, 0x36, 0x18, 0x72, 0x9d, 0x7c, 0x56, 0xb7 };
    uint8_t exp_hi[16] = { 0xe4, 0x8b, 0xea, 0xb5, 0x05, 0xe0, 0x0e, 0x23, 0x01, 0xda, 0x4e, 0x9f, 0xb2, 0xc5, 0x01, 0x7f };

    uint8_t out_hi[16], out_lo[16];
    __m128i r1, r2, r3, r4;
    int result;

    memcpy(&r1, in_a, 16);
    memcpy(&r2, in_b, 16);
    
    clmult(&r3, &r4, r1, r2);
    memcpy(out_hi, &r3, 16);
    memcpy(out_lo, &r4, 16);
    
    result = memcmp(exp_lo, out_lo, 16);
    assert(result == 0);
    
    result = memcmp(exp_hi, out_hi, 16);
    assert(result == 0);
    
    clmult(&r3, &r4, r2, r1);
    memcpy(out_hi, &r3, 16);
    memcpy(out_lo, &r4, 16);
    
    result = memcmp(exp_lo, out_lo, 16);
    assert(result == 0);
    
    result = memcmp(exp_hi, out_hi, 16);
    assert(result == 0);
}

int main(void)
{
    test_reduce_1();

    test_multx_1();
    test_multx_2();
    test_multx_3();

    test_swap_1();

    test_clmul_1();
    test_clmul_2();
    return 0;
}
