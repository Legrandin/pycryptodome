#include "endianess.h"
#include <assert.h>
#include "ed25519.h"

void mul_25519(uint32_t out[10], const uint32_t f[10], const uint32_t g[10]);
void invert_25519(uint32_t out[10], const uint32_t x[10]);
int convert_behex_to_le25p5(uint32_t out[10], const char *in);
int convert_le25p5_to_behex(char **out, uint32_t in[10]);
void convert_le25p5_to_le8(uint8_t out[32], const uint32_t in[10]);
void convert_le8_to_le25p5(uint32_t out[10], const uint8_t in[32]);

/* Add G to PAI */
void test_point_add_1(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char PAIx_hex[] = "0000000000000000000000000000000000000000000000000000000000000000";
    char PAIy_hex[] = "0000000000000000000000000000000000000000000000000000000000000001";

    Point G, Gout;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);
    memset(&Gout, 0, sizeof Gout);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    convert_behex_to_le25p5(Gout.X, PAIx_hex);
    convert_behex_to_le25p5(Gout.Y, PAIy_hex);
    Gout.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    res = ed25519_add(&Gout, &G);
    assert(res == 0);

    invert_25519(invz, Gout.Z);

    /* Check X */
    mul_25519(Gout.X, Gout.X, invz);
    convert_le25p5_to_behex(&c, Gout.X);
    assert(0 == strcmp(c, Gx_hex));
    free(c);

    /* Check Y */
    mul_25519(Gout.Y, Gout.Y, invz);
    convert_le25p5_to_behex(&c, Gout.Y);
    assert(0 == strcmp(c, Gy_hex));
    free(c);
}

/* Add G to G */
void test_point_add_2(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char G2x_hex[] = "36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e";
    char G2y_hex[] = "2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9";

    Point G, G2;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);
    memset(&G2, 0, sizeof G2);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    G2 = G;

    res = ed25519_add(&G2, &G);
    assert(res == 0);
    invert_25519(invz, G2.Z);

    /* Check X */
    mul_25519(G2.X, G2.X, invz);
    convert_le25p5_to_behex(&c, G2.X);
    assert(0 == strcmp(c, G2x_hex));
    free(c);

    /* Check Y */
    mul_25519(G2.Y, G2.Y, invz);
    convert_le25p5_to_behex(&c, G2.Y);
    assert(0 == strcmp(c, G2y_hex));
    free(c);
}

/* Double the PAI */
void test_point_double_1(void)
{
    char PAIx_hex[] = "0000000000000000000000000000000000000000000000000000000000000000";
    char PAIy_hex[] = "0000000000000000000000000000000000000000000000000000000000000001";

    Point PAI;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&PAI, 0, sizeof PAI);

    convert_behex_to_le25p5(PAI.X, PAIx_hex);
    convert_behex_to_le25p5(PAI.Y, PAIy_hex);
    PAI.Z[0] = 1;
    mul_25519(PAI.T, PAI.X, PAI.Y);

    res = ed25519_double(&PAI);
    assert(res == 0);
    invert_25519(invz, PAI.Z);

    /* Check X */
    mul_25519(PAI.X, PAI.X, invz);
    convert_le25p5_to_behex(&c, PAI.X);
    assert(0 == strcmp(c, PAIx_hex));
    free(c);

    /* Check Y */
    mul_25519(PAI.Y, PAI.Y, invz);
    convert_le25p5_to_behex(&c, PAI.Y);
    assert(0 == strcmp(c, PAIy_hex));
    free(c);
}

/* Add G to 2G */
void test_point_add_3(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char G2x_hex[] = "36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e";
    char G2y_hex[] = "2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9";
    char G3x_hex[] = "67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c";
    char G3y_hex[] = "1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4";

    Point G, G2;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);
    memset(&G2, 0, sizeof G2);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    convert_behex_to_le25p5(G2.X, G2x_hex);
    convert_behex_to_le25p5(G2.Y, G2y_hex);
    G2.Z[0] = 1;
    mul_25519(G2.T, G2.X, G2.Y);

    res = ed25519_add(&G2, &G);
    assert(res == 0);
    invert_25519(invz, G2.Z);

    /* Check X */
    mul_25519(G2.X, G2.X, invz);
    convert_le25p5_to_behex(&c, G2.X);
    assert(0 == strcmp(c, G3x_hex));
    free(c);

    /* Check Y */
    mul_25519(G2.Y, G2.Y, invz);
    convert_le25p5_to_behex(&c, G2.Y);
    assert(0 == strcmp(c, G3y_hex));
    free(c);
}

/* Double G */
void test_point_double_2(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char G2x_hex[] = "36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e";
    char G2y_hex[] = "2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9";

    Point G, G2;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    G2 = G;

    res = ed25519_double(&G2);
    assert(res == 0);
    invert_25519(invz, G2.Z);

    /* Check X */
    mul_25519(G2.X, G2.X, invz);
    convert_le25p5_to_behex(&c, G2.X);
    assert(0 == strcmp(c, G2x_hex));
    free(c);

    /* Check Y */
    mul_25519(G2.Y, G2.Y, invz);
    convert_le25p5_to_behex(&c, G2.Y);
    assert(0 == strcmp(c, G2y_hex));
    free(c);
}

void from_affine(Point *P, const uint8_t x[32], const uint8_t y[32])
{
    memset(P, 0, sizeof *P);
    convert_le8_to_le25p5(P->X, x);
    convert_le8_to_le25p5(P->Y, y);
    P->Z[0] = 1;
    mul_25519(P->T, P->X, P->Y);
}

void to_affine(uint8_t x[32], uint8_t y[32], const Point *P)
{
    uint32_t invz[10];
    uint32_t tmp[10];

    invert_25519(invz, P->Z);
    mul_25519(tmp, P->X, invz);
    convert_le25p5_to_le8(x, tmp);
    mul_25519(tmp, P->Y, invz);
    convert_le25p5_to_le8(y, tmp);
}

void test_scalar_mult(void)
{
    uint8_t xout[32], yout[32];

    uint8_t G0x[32] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    uint8_t G0y[32] = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    uint8_t Gx[32]  = "\x1a\xd5\x25\x8f\x60\x2d\x56\xc9\xb2\xa7\x25\x95\x60\xc7\x2c\x69\x5c\xdc\xd6\xfd\x31\xe2\xa4\xc0\xfe\x53\x6e\xcd\xd3\x36\x69\x21";
    uint8_t Gy[32]  = "\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66";
    uint8_t G2x[32] = "\x0e\xce\x43\x28\x4e\xa1\xc5\x83\x5f\xa4\xd7\x15\x45\x8e\x0d\x08\xac\xe7\x33\x18\x7d\x3b\x04\x3d\x6c\x04\x5a\x9f\x4c\x38\xab\x36";
    uint8_t G2y[32] = "\xc9\xa3\xf8\x6a\xae\x46\x5f\x0e\x56\x51\x38\x64\x51\x0f\x39\x97\x56\x1f\xa2\xc9\xe8\x5e\xa2\x1d\xc2\x29\x23\x09\xf3\xcd\x60\x22";
    uint8_t G5y[32] = "\xED\xC8\x76\xD6\x83\x1F\xD2\x10\x5D\x0B\x43\x89\xCA\x2E\x28\x31\x66\x46\x92\x89\x14\x6E\x2C\xE0\x6F\xAE\xFE\x98\xB2\x25\x48\x5F";
    uint8_t Gry[32] = "\xC9\x72\x8D\x51\x1D\xF5\xB3\x05\x12\xD4\x81\xCC\x41\xDE\x72\x0E\x73\x90\xF1\x53\xFE\xF6\xF0\x59\xDC\xF4\xB8\xAF\xEE\x92\x77\x16";

    Point Q;
    int res;

    /* 0 */
    from_affine(&Q, Gx, Gy);
    res = ed25519_scalar(&Q, (uint8_t*)"\x00", 1, 0);
    assert(res == 0);
    to_affine(xout, yout, &Q);
    assert(0 == memcmp(G0x, xout, sizeof G0x));
    assert(0 == memcmp(G0y, yout, sizeof G0y));

    /* 1 */
    from_affine(&Q, Gx, Gy);
    res = ed25519_scalar(&Q, (uint8_t*)"\x01", 1, 0);
    assert(res == 0);
    to_affine(xout, yout, &Q);
    assert(0 == memcmp(Gx, xout, sizeof Gx));
    assert(0 == memcmp(Gy, yout, sizeof Gy));

    /* 2 */
    from_affine(&Q, Gx, Gy);
    res = ed25519_scalar(&Q, (uint8_t*)"\x02", 1, 0);
    assert(res == 0);
    to_affine(xout, yout, &Q);
    assert(0 == memcmp(G2x, xout, sizeof G2x));
    assert(0 == memcmp(G2y, yout, sizeof G2y));

    /* 5 */
    from_affine(&Q, Gx, Gy);
    res = ed25519_scalar(&Q, (uint8_t*)"\x05", 1, 0);
    assert(res == 0);
    to_affine(xout, yout, &Q);
    assert(0 == memcmp(G5y, yout, sizeof G5y));

    /* random */
    uint8_t r[32] = "\x08\x68\xba\x7a\x34\x73\x4f\x3e\x93\xdd\x24\x26\x32\x7f\x0f\x34\x14\x5c\xd9\x43\x02\xe4\xd5\xdd\x95\x00\xee\x1b\x57\x11\x39\xdd";

    from_affine(&Q, Gx, Gy);
    res = ed25519_scalar(&Q, r, 32, 0);
    assert(res == 0);
    to_affine(xout, yout, &Q);
    assert(0 == memcmp(Gry, yout, sizeof Gry));
}

void test_cmp_1(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";

    Point G, *P;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    res = ed25519_clone(&P, &G);
    assert(res == 0);

    invert_25519(invz, P->Z);

    /* Check X */
    mul_25519(P->X, P->X, invz);
    convert_le25p5_to_behex(&c, P->X);
    assert(0 == strcmp(c, Gx_hex));
    free(c);

    /* Check Y */
    mul_25519(P->Y, P->Y, invz);
    convert_le25p5_to_behex(&c, P->Y);
    assert(0 == strcmp(c, Gy_hex));
    free(c);

    ed25519_free_point(P);
}

void test_neg_1(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char Gnegx_hex[] = "5e96c92c3291ac013f5b1dce022923a396d3389f6ada584d36a9d29f70da2ad3";
    char Gnegy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";

    Point G;
    uint32_t invz[10];
    char *c;
    int res;

    memset(&G, 0, sizeof G);

    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    res = ed25519_neg(&G);
    assert(res == 0);

    invert_25519(invz, G.Z);

    /* Check X */
    mul_25519(G.X, G.X, invz);
    convert_le25p5_to_behex(&c, G.X);
    assert(0 == strcmp(c, Gnegx_hex));
    free(c);

    /* Check Y */
    mul_25519(G.Y, G.Y, invz);
    convert_le25p5_to_behex(&c, G.Y);
    assert(0 == strcmp(c, Gnegy_hex));
    free(c);
}

int main(void)
{
    test_point_add_1();
    test_point_add_2();
    test_point_add_3();
    test_point_double_1();
    test_point_double_2();
    test_scalar_mult();
    test_cmp_1();
    test_neg_1();
    return 0;
}
