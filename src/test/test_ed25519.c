#include "endianess.h"
#include <assert.h>
#include "ed25519.h"

void mul_25519(uint32_t out[10], const uint32_t f[10], const uint32_t g[10]);
void invert_25519(uint32_t out[10], const uint32_t x[10]);
int convert_behex_to_le25p5(uint32_t out[10], const char *in);
int convert_le25p5_to_behex(char **out, uint32_t in[10]);
void convert_le25p5_to_le8(uint8_t out[32], const uint32_t in[10]);
void convert_le8_to_le25p5(uint32_t out[10], const uint8_t in[32]);
void sub_25519(uint32_t out[10], const uint32_t a[10], const uint32_t b[10]);
void ed25519_add_internal(Point *P3, const Point *P1, const Point *P2);

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

    const uint8_t G0x[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t G0y[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t Gx[32] = {0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
                            0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
                            0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
                            0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21};
    const uint8_t Gy[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    const uint8_t G2x[32] = {0x0E, 0xCE, 0x43, 0x28, 0x4E, 0xA1, 0xC5, 0x83,
                             0x5F, 0xA4, 0xD7, 0x15, 0x45, 0x8E, 0x0D, 0x08,
                             0xAC, 0xE7, 0x33, 0x18, 0x7D, 0x3B, 0x04, 0x3D,
                             0x6C, 0x04, 0x5A, 0x9F, 0x4C, 0x38, 0xAB, 0x36};
    const uint8_t G2y[32] = {0xC9, 0xA3, 0xF8, 0x6A, 0xAE, 0x46, 0x5F, 0x0E,
                             0x56, 0x51, 0x38, 0x64, 0x51, 0x0F, 0x39, 0x97,
                             0x56, 0x1F, 0xA2, 0xC9, 0xE8, 0x5E, 0xA2, 0x1D,
                             0xC2, 0x29, 0x23, 0x09, 0xF3, 0xCD, 0x60, 0x22};
    const uint8_t G5y[32] = {0xED, 0xC8, 0x76, 0xD6, 0x83, 0x1F, 0xD2, 0x10,
                             0x5D, 0x0B, 0x43, 0x89, 0xCA, 0x2E, 0x28, 0x31,
                             0x66, 0x46, 0x92, 0x89, 0x14, 0x6E, 0x2C, 0xE0,
                             0x6F, 0xAE, 0xFE, 0x98, 0xB2, 0x25, 0x48, 0x5F};
    const uint8_t Gry[32] = {0xC9, 0x72, 0x8D, 0x51, 0x1D, 0xF5, 0xB3, 0x05,
                             0x12, 0xD4, 0x81, 0xCC, 0x41, 0xDE, 0x72, 0x0E,
                             0x73, 0x90, 0xF1, 0x53, 0xFE, 0xF6, 0xF0, 0x59,
                             0xDC, 0xF4, 0xB8, 0xAF, 0xEE, 0x92, 0x77, 0x16};
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
    const uint8_t r[32] = {0x08, 0x68, 0xBA, 0x7A, 0x34, 0x73, 0x4F, 0x3E,
                           0x93, 0xDD, 0x24, 0x26, 0x32, 0x7F, 0x0F, 0x34,
                           0x14, 0x5C, 0xD9, 0x43, 0x02, 0xE4, 0xD5, 0xDD,
                           0x95, 0x00, 0xEE, 0x1B, 0x57, 0x11, 0x39, 0xDD};

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

/* k*P by double-and-add, without blinding (k big-endian, public) */
static void ref_scalar(Point *out, const uint8_t *k, size_t len, const Point *P)
{
    size_t i;
    int j;

    memset(out, 0, sizeof *out);
    out->Y[0] = out->Z[0] = 1;
    for (i=0; i<len; i++) {
        for (j=7; j>=0; j--) {
            ed25519_double(out);
            if ((k[i] >> j) & 1)
                ed25519_add(out, P);
        }
    }
}

/*
 * The blinded scalar multiplication gives the same result for any seed,
 * also for a point with a component of order 8 (G + T8), and for scalars
 * shorter or longer than the blinded one.
 * The multiplication for public scalars gives the same result too.
 */
void test_scalar_blinding(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    char T8x_hex[] = "1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a";
    char T8y_hex[] = "7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7";
    static const size_t lens[] = { 1, 32, 64 };
    uint8_t k[64];
    Point P[2], Q, R;
    unsigned i, l, n;
    uint64_t seed;

    memset(P, 0, sizeof P);
    convert_behex_to_le25p5(P[0].X, Gx_hex);
    convert_behex_to_le25p5(P[0].Y, Gy_hex);
    P[0].Z[0] = 1;
    mul_25519(P[0].T, P[0].X, P[0].Y);

    /* P[1] = G + T8 */
    convert_behex_to_le25p5(P[1].X, T8x_hex);
    convert_behex_to_le25p5(P[1].Y, T8y_hex);
    P[1].Z[0] = 1;
    mul_25519(P[1].T, P[1].X, P[1].Y);
    assert(ed25519_add(&P[1], &P[0]) == 0);

    for (i=0; i<sizeof k; i++)
        k[i] = (uint8_t)(i*37 + 11);

    for (n=0; n<2; n++) {
        for (l=0; l<sizeof lens / sizeof lens[0]; l++) {
            ref_scalar(&R, k, lens[l], &P[n]);
            Q = P[n];
            assert(ed25519_scalar_public(&Q, k, lens[l]) == 0);
            assert(ed25519_cmp(&Q, &R) == 0);
            for (seed=0; seed<16; seed++) {
                Q = P[n];
                assert(ed25519_scalar(&Q, k, lens[l], seed * 0x9E3779B97F4A7C15ULL) == 0);
                assert(ed25519_cmp(&Q, &R) == 0);
            }
        }
    }
}

/* The encoding of RFC 8032 (5.1.2) of P */
static void encode_point(uint8_t enc[32], const Point *P)
{
    uint8_t x[32];

    to_affine(x, enc, P);
    enc[31] |= (uint8_t)((x[0] & 1) << 7);
}

/* Decode an encoding of P (or fail with error), and check that it gives P back */
static void check_decode(const uint8_t enc[32], const Point *P, int error)
{
    Point *Q = NULL;

    assert(ed25519_decode_point(&Q, enc, 32, NULL) == error);
    if (error) {
        assert(Q == NULL);
        return;
    }
    assert(ed25519_cmp(Q, P) == 0);
    ed25519_free_point(Q);
}

void test_decode_point(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    uint8_t enc[32];
    Point G, P, *Q;
    unsigned i;

    memset(&G, 0, sizeof G);
    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    /* Round trip of G, 2G, ..., 16G (both parities of x, both roots) */
    P = G;
    for (i=1; i<=16; i++) {
        encode_point(enc, &P);
        check_decode(enc, &P, 0);
        ed25519_add_internal(&P, &P, &G);
    }

    /* The neutral point (0, 1): x = 0 cannot have its bit set */
    memset(&P, 0, sizeof P);
    P.Y[0] = P.Z[0] = 1;
    memset(enc, 0, 32);
    enc[0] = 1;
    check_decode(enc, &P, 0);
    enc[31] = 0x80;
    check_decode(enc, &P, ERR_EC_POINT);

    /* The point of order 2 (0, -1) */
    sub_25519(P.Y, P.T, P.Y);
    memset(enc, 0xFF, 32);
    enc[0] = 0xEC;
    enc[31] = 0x7F;
    check_decode(enc, &P, 0);
    enc[31] = 0xFF;
    check_decode(enc, &P, ERR_EC_POINT);

    /* y = p, p + 1 and 2^255 - 1 are not reduced (with both values of the bit) */
    for (i=0; i<3; i++) {
        memset(enc, 0xFF, 32);
        enc[0] = i == 0 ? 0xED : (i == 1 ? 0xEE : 0xFF);
        enc[31] = 0x7F;
        check_decode(enc, NULL, ERR_EC_POINT);
        enc[31] = 0xFF;
        check_decode(enc, NULL, ERR_EC_POINT);
    }

    /* y = 2 has no x; y = 3 has one, on the curve */
    memset(enc, 0, 32);
    enc[0] = 2;
    check_decode(enc, NULL, ERR_EC_POINT);
    enc[0] = 3;
    assert(ed25519_decode_point(&Q, enc, 32, NULL) == 0);
    {
        uint8_t xb[32], yb[32];
        Point *R;

        assert(ed25519_get_xy(xb, yb, 32, Q) == 0);
        assert(ed25519_new_point(&R, xb, yb, 32, NULL) == 0);
        assert(ed25519_cmp(Q, R) == 0);
        ed25519_free_point(R);
    }
    ed25519_free_point(Q);

    /* Wrong length */
    assert(ed25519_decode_point(&Q, enc, 31, NULL) == ERR_MODULUS);
}

/*
 * The fixed-base multiplication (table, for B with Z = 1) gives the same
 * result as the ladder (B with Z = 2, not recognized as the base point),
 * blinded and public, for scalars of all the lengths up to the limit of
 * the table (36 bytes) and beyond, and for edge values.
 */
void test_scalar_base(void)
{
    char Gx_hex[] = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    char Gy_hex[] = "6666666666666666666666666666666666666666666666666666666666666658";
    /* L, big-endian */
    static const uint8_t order[32] = {
        0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed };
    uint32_t two[10] = { 2 };
    uint64_t state = 1;
    uint8_t k[40];
    Point G, G2, P, Q;
    unsigned t, len, i;

    memset(&G, 0, sizeof G);
    convert_behex_to_le25p5(G.X, Gx_hex);
    convert_behex_to_le25p5(G.Y, Gy_hex);
    G.Z[0] = 1;
    mul_25519(G.T, G.X, G.Y);

    /* The same point, with Z = 2 */
    mul_25519(G2.X, G.X, two);
    mul_25519(G2.Y, G.Y, two);
    mul_25519(G2.Z, G.Z, two);
    mul_25519(G2.T, G.T, two);

    for (t=0; t<600 + 6; t++) {
        len = t < 600 ? 1 + t % 37 : 32;
        for (i=0; i<len; i++) {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            k[i] = (uint8_t)(state >> 56);
        }
        if (t >= 600) {
            switch (t - 600) {
            case 0: memset(k, 0, 32); break;                    /* 0 */
            case 1: memset(k, 0xFF, 32); break;                 /* 2^256 - 1 */
            case 2: memcpy(k, order, 32); break;                /* L */
            case 3: memcpy(k, order, 32); k[31]--; break;       /* L - 1 */
            case 4: memcpy(k, order, 32); k[31]++; break;       /* L + 1 */
            case 5: memset(k, 0x88, 32); break;                 /* all digits 8 */
            }
        }

        P = G;
        Q = G2;
        assert(ed25519_scalar(&P, k, len, state) == 0);
        assert(ed25519_scalar(&Q, k, len, state ^ 1) == 0);
        assert(ed25519_cmp(&P, &Q) == 0);

        P = G;
        assert(ed25519_scalar_public(&P, k, len) == 0);
        assert(ed25519_cmp(&P, &Q) == 0);
    }
}

int main(void)
{
    test_point_add_1();
    test_point_add_2();
    test_point_add_3();
    test_point_double_1();
    test_point_double_2();
    test_scalar_mult();
    test_scalar_blinding();
    test_scalar_base();
    test_cmp_1();
    test_neg_1();
    test_decode_point();
    return 0;
}
