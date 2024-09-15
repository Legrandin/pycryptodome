#include "endianess.h"
#include "curve25519.h"
#include <assert.h>

void mul_25519(uint32_t out[10], const uint32_t f[10], const uint32_t g[10]);
int convert_behex_to_le25p5(uint32_t out[10], const char *in);
void curve25519_scalar_internal(Point *Pout,
                                const uint8_t *k, size_t len,
                                const Point *Pin);
int convert_le25p5_to_behex(char **out, uint32_t in[10]);

void print_point(Point *p)
{
    char *out_x, *out_z;

    convert_le25p5_to_behex(&out_x, p->X);
    convert_le25p5_to_behex(&out_z, p->Z);

    printf("X=%s\n", out_x);
    printf("Z=%s\n", out_z);

    free(out_x);
    free(out_z);
}

void test_ladder_1(void)
{
    /* All in big endian format */
    uint8_t scalar[32] = {0xC4,0x9A,0x44,0xBA,0x44,0x22,0x6A,0x50,
                          0x18,0x5A,0xFC,0xC1,0x0A,0x4C,0x14,0x62,
                          0xDD,0x5E,0x46,0x82,0x4B,0x15,0x16,0x3B,
                          0x9D,0x7C,0x52,0xF0,0x6B,0xE3,0x46,0xA5};
    uint8_t pubkey[32] = {0x4C,0x1C,0xAB,0xD0,0xA6,0x03,0xA9,0x10,
                          0x3B,0x35,0xB3,0x26,0xEC,0x24,0x66,0x72,
                          0x7C,0x5F,0xB1,0x24,0xA4,0xC1,0x94,0x35,
                          0xDB,0x30,0x30,0x58,0x67,0x68,0xDB,0xE6};
    uint8_t expout[32] = {0x52,0x85,0xA2,0x77,0x55,0x07,0xB4,0x54,
                          0xF7,0x71,0x1C,0x49,0x03,0xCF,0xEC,0x32,
                          0x4F,0x08,0x8D,0xF2,0x4D,0xEA,0x94,0x8E,
                          0x90,0xC6,0xE9,0x9D,0x37,0x55,0xDA,0xC3};
    uint8_t out[32];

    Point *Pin;
    Point Pout;

    curve25519_new_point(&Pin, pubkey, 32, NULL);

    /* Clamping BE/LE */
    scalar[31-0] &= 248;
    scalar[31-31] &= 127;
    scalar[31-31] |= 64;

    curve25519_scalar_internal(&Pout, scalar, 32, Pin);

    curve25519_get_x(out, 32, &Pout);

    assert(0 == memcmp(out, expout, 32));

    curve25519_free_point(Pin);
}

void test_ladder_2(void)
{
    uint8_t scalar[] = { 0 };
    uint8_t zeroes32[32] = { 0 };
    Point G, Pout;

    memset(&G, 0, sizeof G);
    G.X[0] = 9;
    G.Z[0] = 1;

    curve25519_scalar_internal(&Pout, scalar, sizeof scalar, &G);
    assert(memcmp(Pout.Z, zeroes32, 32) == 0);
}

void test_cmp_1(void)
{
    char c1_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char c2_hex[] = "0190378b378393023782223892baa783fff998e12a89bcede8abdedfffffffff";

    Point G, P;
    int res;

    memset(&G, 0, sizeof G);
    memset(&P, 0, sizeof P);

    // G = (C1, 1)
    convert_behex_to_le25p5(G.X, c1_hex);
    G.Z[0] = 1;

    // P = (C1*C2, C2)
    convert_behex_to_le25p5(P.Z, c2_hex);
    mul_25519(P.X, G.X, P.Z);

    res = curve25519_cmp(&G, &P);
    assert(res == 0);

    G.Z[0] = 2;
    // G = (C1, 2)
    res = curve25519_cmp(&G, &P);
    assert(res != 0);
}

void test_cmp_2(void)
{
    char c1_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";

    Point G, P;
    int res;

    memset(&G, 0, sizeof G);
    memset(&P, 0, sizeof P);

    // G = (C1, 1)
    convert_behex_to_le25p5(G.X, c1_hex);
    G.Z[0] = 1;

    // P = (1, 0)
    P.X[0] = 1;
    res = curve25519_cmp(&G, &P);
    assert(res != 0);
}

void test_small_group(void)
{
    char c1_hex[] = "00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0";
    Point G, P;
    const uint8_t scalar[] = { 8 };
    uint8_t zeroes32[32] = { 0 };

    memset(&G, 0, sizeof G);
    memset(&P, 0, sizeof P);

    convert_behex_to_le25p5(G.X, c1_hex);
    G.Z[0] = 1;

    curve25519_scalar_internal(&P, scalar, 1, &G);

    assert(memcmp(P.Z, zeroes32, 32) == 0);
}

int main(void)
{
    test_ladder_1();
    test_ladder_2();
    test_cmp_1();
    test_cmp_2();
    test_small_group();
    return 0;
}
