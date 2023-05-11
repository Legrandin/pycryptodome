#include "common.h"
#include <wmmintrin.h>
#include <stdio.h>

enum SubType { OnlySub, SubRotXor };
uint32_t sub_rot(uint32_t w, unsigned idx /** round/Nk **/, enum SubType subType);
int expand_key(__m128i *erk, __m128i *drk, const uint8_t *key, unsigned Nk, unsigned Nr);
int internal_AESNI_encrypt(__m128i r[], unsigned rounds, const uint8_t *in, uint8_t *out, size_t data_len);

void test_sub_rot(void)
{
    uint32_t res[] = {
        0xC116EA4A,
        0xC116EA49,
        0xC116EA4F,
        0xC116EA43,
        0xC116EA5B,
        0xC116EA6B,
        0xC116EA0B,
        0xC116EACB,
        0xC116EA50,
        0xC116EA7D
    };

    for (int i=1; i<=10; i++) {
        assert(res[i-1] == sub_rot(0xFFBBCCDD, i, SubRotXor));
    }

    assert(0x16EA4BC1 == sub_rot(0xFFBBCCDD, 4, OnlySub));
}

int m128i_m128i_differ(__m128i a, __m128i b)
{
    int mask;
    __m128i result;
    result = _mm_cmpeq_epi32(a, b);
    mask = _mm_movemask_epi8(result);
    return mask != 0xFFFF;
}

int m128i_array_differ(__m128i a, const uint8_t *ref)
{
    uint8_t *array;
    unsigned i;
    array = (uint8_t*)align_alloc(16, 16);
    _mm_storeu_si128((__m128i*)array, a);
    for (i=0; i<16; i++) {
        if (array[i] != ref[i])
            return -1;
    }
    align_free(array);
    return 0;
}

int array16_differ(const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i=0; i<16; i++) {
        if (a[i] != b[i])
            return -1;
    }
    return 0;
}

void test_expand_key_128(void)
{
    uint8_t key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 , 13, 14, 15 };
    __m128i *erk;
    __m128i *drk;
    const uint8_t drk_1[16] = { 19, 170, 41, 190, 156, 143, 175, 246, 247, 112, 245, 128, 0, 247, 191, 3 };
    const uint8_t drk_9[16] = { 140, 86, 223, 240, 130, 93, 211, 249, 128, 90, 211, 252, 134, 89, 215, 253 };
    const uint8_t erk_1[16] = {214, 170, 116, 253, 210, 175, 114, 250, 218, 166, 120, 241, 214, 171, 118, 254};
    const uint8_t erk_9[16] = {84, 153, 50, 209, 240, 133, 87, 104, 16, 147, 237, 156, 190, 44, 151, 78};

    erk = (__m128i*)align_alloc(16*11, 16);
    drk = (__m128i*)align_alloc(16*11, 16);

    expand_key(erk, drk, key, 4, 10);

    assert(m128i_m128i_differ(erk[0], drk[10]) == 0);
    assert(m128i_m128i_differ(erk[10], drk[0]) == 0);

    assert(m128i_array_differ(erk[1], erk_1) == 0);
    assert(m128i_array_differ(erk[9], erk_9) == 0);
    assert(m128i_array_differ(drk[1], drk_1) == 0);
    assert(m128i_array_differ(drk[9], drk_9) == 0);

    align_free(erk);
    align_free(drk);
}

void test_encrypt_128(void)
{
    uint8_t key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 , 13, 14, 15 };
    uint8_t pt[16] = { 21, 23, 89, 2, 209, 2, 45, 1, 233, 190, 23, 1, 2, 2, 1, 5 };
    uint8_t ct[16];
    uint8_t ct_ref[16] = { 166, 206, 231, 70, 200, 68, 178, 80, 55, 156, 105, 27, 230, 75, 80, 178};
    uint8_t *pt_big, *ct_big;
    __m128i *erk;
    __m128i *drk;
    int result;
    int i;

    erk = (__m128i*)align_alloc(16*11, 16);
    drk = (__m128i*)align_alloc(16*11, 16);

    expand_key(erk, drk, key, 4, 10);

    /* 1 block */
    result = internal_AESNI_encrypt(erk, 10, pt, ct, 16);
    assert(result == 0);
    assert(array16_differ(ct, ct_ref) == 0);

    /* 8 blocks */
    pt_big = malloc(16*8);
    ct_big = malloc(16*8);
    for (i=0; i<8; i++)
        memcpy(pt_big + 16*i, pt, 16);
    result = internal_AESNI_encrypt(erk, 10, pt_big, ct_big, 16*8);
    for (i=0; i<8; i++)
        assert(array16_differ(ct_big + 16*i, ct_ref) == 0);
    free(pt_big);
    free(ct_big);

    /* 8+1 blocks */
    pt_big = malloc(16*9);
    ct_big = malloc(16*9);
    for (i=0; i<9; i++)
        memcpy(pt_big + 16*i, pt, 16);
    result = internal_AESNI_encrypt(erk, 10, pt_big, ct_big, 16*9);
    for (i=0; i<9; i++)
        assert(array16_differ(ct_big + 16*i, ct_ref) == 0);
    free(pt_big);
    free(ct_big);

    /* partial block */
    result = internal_AESNI_encrypt(erk, 10, pt, ct, 15);
    assert(result != 0);

    align_free(erk);
    align_free(drk);
}

int main(void)
{
    test_sub_rot();
    test_expand_key_128();
    test_encrypt_128();
    return 0;
}
