#include "endianess.h"
#include <assert.h>

void ladder(uint8_t shared_secret[32], const uint8_t *k, size_t len, const uint8_t pubkey[32]);

void test_ladder(void)
{
    uint8_t scalar[32] = {0xA5, 0x46, 0xE3, 0x6B, 0xF0, 0x52, 0x7C, 0x9D,
                          0x3B, 0x16, 0x15, 0x4B, 0x82, 0x46, 0x5E, 0xDD,
                          0x62, 0x14, 0x4C, 0x0A, 0xC1, 0xFC, 0x5A, 0x18,
                          0x50, 0x6A, 0x22, 0x44, 0xBA, 0x44, 0x9A, 0xC4};
    uint8_t pubkey[32] = {0xE6, 0xDB, 0x68, 0x67, 0x58, 0x30, 0x30, 0xDB,
                          0x35, 0x94, 0xC1, 0xA4, 0x24, 0xB1, 0x5F, 0x7C,
                          0x72, 0x66, 0x24, 0xEC, 0x26, 0xB3, 0x35, 0x3B,
                          0x10, 0xA9, 0x03, 0xA6, 0xD0, 0xAB, 0x1C, 0x4C};
    uint8_t expout[32] = {0xC3, 0xDA, 0x55, 0x37, 0x9D, 0xE9, 0xC6, 0x90,
                          0x8E, 0x94, 0xEA, 0x4D, 0xF2, 0x8D, 0x08, 0x4F,
                          0x32, 0xEC, 0xCF, 0x03, 0x49, 0x1C, 0x71, 0xF7,
                          0x54, 0xB4, 0x07, 0x55, 0x77, 0xA2, 0x85, 0x52};
    uint8_t out[32];

    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    ladder(out, scalar, 32, pubkey);
    assert(0 == memcmp(out, expout, 32));
}

int main(void)
{
    test_ladder();
    return 0;
}
