/*
 * Test of AES with the ARMv8 Cryptography Extensions (AES_armv8.c):
 * the FIPS 197 examples, and the same output as the portable AES (AES.c)
 * for every key size and for 0 to 20 blocks (the code processes 8 blocks
 * at a time, then one at a time).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "block_base.h"

int AES_start_operation(const uint8_t key[], size_t key_len, BlockBase **pResult);
int AES_ARMV8_start_operation(const uint8_t key[], size_t key_len, BlockBase **pResult);
uint32_t sub_word(uint32_t w);

static void random_bytes(uint8_t *p, size_t len)
{
    size_t i;

    for (i=0; i<len; i++)
        p[i] = (uint8_t)rand();
}

static void test_sub_word(void)
{
    assert(sub_word(0xFFBBCCDD) == 0x16EA4BC1);
    assert(sub_word(0) == 0x63636363);
}

/** FIPS 197, Appendix C **/
static void test_fips197(void)
{
    static const uint8_t ct_ref[3][16] = {
        { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a },
        { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 },
        { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 },
    };
    uint8_t key[32], pt[16], ct[16], pt2[16];
    unsigned i;

    for (i=0; i<32; i++)
        key[i] = (uint8_t)i;
    for (i=0; i<16; i++)
        pt[i] = (uint8_t)(i*0x11);

    for (i=0; i<3; i++) {
        BlockBase *bb;

        assert(0 == AES_ARMV8_start_operation(key, 16+8*i, &bb));
        assert(0 == bb->encrypt(bb, pt, ct, 16));
        assert(0 == memcmp(ct, ct_ref[i], 16));
        assert(0 == bb->decrypt(bb, ct, pt2, 16));
        assert(0 == memcmp(pt, pt2, 16));
        bb->destructor(bb);
    }
}

/** Same output as the portable AES **/
static void test_against_portable(void)
{
    uint8_t key[32], in[16*20], out1[16*20], out2[16*20];
    size_t key_len, blocks;

    for (key_len=16; key_len<=32; key_len+=8) {
        BlockBase *ref, *bb;

        random_bytes(key, key_len);
        assert(0 == AES_start_operation(key, key_len, &ref));
        assert(0 == AES_ARMV8_start_operation(key, key_len, &bb));

        for (blocks=0; blocks<=20; blocks++) {
            random_bytes(in, sizeof in);

            assert(0 == ref->encrypt(ref, in, out1, 16*blocks));
            assert(0 == bb->encrypt(bb, in, out2, 16*blocks));
            assert(0 == memcmp(out1, out2, 16*blocks));

            assert(0 == ref->decrypt(ref, in, out1, 16*blocks));
            assert(0 == bb->decrypt(bb, in, out2, 16*blocks));
            assert(0 == memcmp(out1, out2, 16*blocks));
        }

        ref->destructor(ref);
        bb->destructor(bb);
    }
}

static void test_errors(void)
{
    uint8_t key[32] = { 0 }, data[16*9] = { 0 };
    BlockBase *bb;

    assert(ERR_NULL == AES_ARMV8_start_operation(NULL, 16, &bb));
    assert(ERR_NULL == AES_ARMV8_start_operation(key, 16, NULL));
    assert(ERR_KEY_SIZE == AES_ARMV8_start_operation(key, 15, &bb));
    assert(ERR_KEY_SIZE == AES_ARMV8_start_operation(key, 33, &bb));

    assert(0 == AES_ARMV8_start_operation(key, 16, &bb));
    assert(ERR_NOT_ENOUGH_DATA == bb->encrypt(bb, data, data, 15));
    assert(ERR_NOT_ENOUGH_DATA == bb->encrypt(bb, data, data, 16*9-1));
    assert(ERR_NOT_ENOUGH_DATA == bb->decrypt(bb, data, data, 17));
    assert(ERR_NULL == bb->encrypt(bb, NULL, data, 16));
    assert(ERR_NULL == bb->decrypt(bb, data, NULL, 16));
    bb->destructor(bb);
}

int main(void)
{
    test_sub_word();
    test_fips197();
    test_against_portable();
    test_errors();
    return 0;
}
