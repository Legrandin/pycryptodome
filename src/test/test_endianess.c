#include "common.h"
#include <assert.h>

void test_little_32(void)
{
    uint32_t t;
    uint8_t res[4];

    t = 0x04030201U;
    memset(res, 0xFF, 4);
    u32to8_little(res, &t);
    assert(0 == memcmp(res, "\x01\x02\x03\x04", 4));

    t = ~0U;
    u8to32_little(&t, res);
    assert(t == 0x04030201U);

    t = ~0U;
    t = load_u8to32_little(res);
    assert(t == 0x04030201U);


    t = ~0U;
    t = LOAD_U32_LITTLE(res);
    assert(t == 0x04030201U);

    t = 0x04030201U;
    memset(res, 0xFF, 4);
    STORE_U32_LITTLE(res, t);
    assert(0 == memcmp(res, "\x01\x02\x03\x04", 4));
}

void test_big_32(void)
{
    uint32_t t;
    uint8_t res[4];

    t = 0x04030201U;
    memset(res, 0xFF, 4);
    u32to8_big(res, &t);
    assert(0 == memcmp(res, "\x04\x03\x02\x01", 4));

    t = ~0U;
    u8to32_big(&t, res);
    assert(t == 0x04030201U);

    t = ~0U;
    t = load_u8to32_big(res);
    assert(t == 0x04030201U);


    t = ~0U;
    t = LOAD_U32_BIG(res);
    assert(t == 0x04030201U);

    t = 0x04030201U;
    memset(res, 0xFF, 4);
    STORE_U32_BIG(res, t);
    assert(0 == memcmp(res, "\x04\x03\x02\x01", 4));
}

void test_little_64(void)
{
    uint64_t t;
    uint8_t res[8];

    t = 0x0807060504030201UL;
    memset(res, 0xFF, 8);
    u64to8_little(res, &t);
    assert(0 == memcmp(res, "\x01\x02\x03\x04\x05\x06\x07\x08", 8));

    t = ~0UL;
    u8to64_little(&t, res);
    assert(t == 0x0807060504030201UL);

    t = ~0UL;
    t = load_u8to64_little(res);
    assert(t == 0x0807060504030201UL);


    t = ~0UL;
    t = LOAD_U64_LITTLE(res);
    assert(t == 0x0807060504030201UL);

    t = 0x0807060504030201UL;
    memset(res, 0xFF, 8);
    STORE_U64_LITTLE(res, t);
    assert(0 == memcmp(res, "\x01\x02\x03\x04\x05\x06\x07\x08", 8));
}

void test_big_64(void)
{
    uint64_t t;
    uint8_t res[8];

    t = 0x0807060504030201UL;
    memset(res, 0xFF, 8);
    u64to8_big(res, &t);
    assert(0 == memcmp(res, "\x08\x07\x06\x05\x04\x03\x02\x01", 8));

    t = ~0UL;
    u8to64_big(&t, res);
    assert(t == 0x0807060504030201UL);

    t = ~0UL;
    t = load_u8to64_big(res);
    assert(t == 0x0807060504030201UL);


    t = ~0UL;
    t = LOAD_U64_BIG(res);
    assert(t == 0x0807060504030201UL);

    t = 0x0807060504030201UL;
    memset(res, 0xFF, 8);
    STORE_U64_BIG(res, t);
    assert(0 == memcmp(res, "\x08\x07\x06\x05\x04\x03\x02\x01", 8));
}

int main(void)
{
    test_little_32();
    test_big_32();
    test_little_64();
    test_big_64();
    return 0;
}
