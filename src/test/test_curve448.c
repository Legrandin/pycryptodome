/*
 * Unit tests of curve448.c (X448 on the nat library), with the test
 * vectors of RFC 7748 (5.2 and 6.2).
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "nat.h"
#include "ec_common.h"
#include "curve448.h"

#if defined(TEST_BMI2_ADX)
#include <stdio.h>
#include <cpuid.h>

static int have_bmi2_adx(void)
{
    unsigned eax, ebx, ecx, edx;

    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1U << 8)) && (ebx & (1U << 19));
}
#endif

#define LEN 56

/* Private functions (they are not static when STATIC is defined as empty) */
void curve448_ladder_step(EcWs *ws, const Curve448Context *ctx,
                          uint64_t *x2, uint64_t *z2, uint64_t *x3, uint64_t *z3,
                          const uint64_t *x1);
int curve448_ladder(EcWs *ws, const Curve448Context *ctx, Curve448Point *p,
                    const uint8_t *k, size_t len, uint64_t seed);

/* RFC 7748: little-endian scalars and u-coordinates */
static const char *vectors[][3] = {
    { "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
      "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
      "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f" },
    { "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
      "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
      "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d" },
};

/* RFC 7748, 5.2: k = u = 5, then k, u = X448(k, u), k */
static const char *iter_1 = "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113";
static const char *iter_1000 = "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38";

/* RFC 7748, 6.2: Alice's and Bob's private keys, and the shared secret */
static const char *alice_priv = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
static const char *alice_pub = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
static const char *bob_priv = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
static const char *bob_pub = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
static const char *shared = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

static uint64_t rnd_state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return rnd_state;
}

static unsigned hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return (unsigned)(ch - '0');
    assert(ch >= 'a' && ch <= 'f');
    return (unsigned)(ch - 'a' + 10);
}

/** Hex string (little-endian number) to big-endian bytes **/
static void from_hex_le(uint8_t *out, const char *hex)
{
    unsigned i;

    assert(strlen(hex) == 2*LEN);
    for (i=0; i<LEN; i++)
        out[LEN - 1 - i] = (uint8_t)(hex_digit(hex[2*i]) << 4 | hex_digit(hex[2*i + 1]));
}

/** The clamped scalar of RFC 7748 (big-endian) **/
static void clamp(uint8_t *k)
{
    k[LEN - 1] &= 0xFC;
    k[0] |= 0x80;
}

/** out = X448(k, u), all big-endian (k not clamped) **/
static void x448(uint8_t *out, const Curve448Context *ctx, const uint8_t *k_in, const uint8_t *u)
{
    Curve448Point *p;
    uint8_t k[LEN];

    memcpy(k, k_in, LEN);
    clamp(k);
    assert(curve448_new_point(&p, u, LEN, ctx) == 0);
    assert(curve448_scalar(p, k, LEN, rnd()) == 0);
    assert(curve448_get_x(out, LEN, p) == 0);
    curve448_free_point(p);
}

static void test_vectors(const Curve448Context *ctx)
{
    uint8_t k[LEN], u[LEN], expected[LEN], out[LEN];
    unsigned i;

    for (i=0; i<sizeof vectors / sizeof vectors[0]; i++) {
        from_hex_le(k, vectors[i][0]);
        from_hex_le(u, vectors[i][1]);
        from_hex_le(expected, vectors[i][2]);
        x448(out, ctx, k, u);
        assert(memcmp(out, expected, LEN) == 0);
    }
}

static void test_iterations(const Curve448Context *ctx)
{
    uint8_t k[LEN], u[LEN], out[LEN], expected[LEN];
    unsigned i;

    memset(k, 0, LEN);
    k[LEN - 1] = 5;
    memcpy(u, k, LEN);
    for (i=1; i<=1000; i++) {
        x448(out, ctx, k, u);
        memcpy(u, k, LEN);
        memcpy(k, out, LEN);
        if (i == 1) {
            from_hex_le(expected, iter_1);
            assert(memcmp(k, expected, LEN) == 0);
        }
    }
    from_hex_le(expected, iter_1000);
    assert(memcmp(k, expected, LEN) == 0);
}

static void test_dh(const Curve448Context *ctx)
{
    uint8_t a[LEN], b[LEN], five[LEN], pa[LEN], pb[LEN], s1[LEN], s2[LEN], expected[LEN];

    from_hex_le(a, alice_priv);
    from_hex_le(b, bob_priv);
    memset(five, 0, LEN);
    five[LEN - 1] = 5;

    x448(pa, ctx, a, five);
    from_hex_le(expected, alice_pub);
    assert(memcmp(pa, expected, LEN) == 0);
    x448(pb, ctx, b, five);
    from_hex_le(expected, bob_pub);
    assert(memcmp(pb, expected, LEN) == 0);

    x448(s1, ctx, a, pb);
    x448(s2, ctx, b, pa);
    from_hex_le(expected, shared);
    assert(memcmp(s1, expected, LEN) == 0);
    assert(memcmp(s2, expected, LEN) == 0);
}

/* x of k*P with the public API, for P = (5:1) */
static void x_of(uint8_t *out, const Curve448Context *ctx, unsigned k)
{
    Curve448Point *p;
    uint8_t five = 5, kb[2];

    kb[0] = (uint8_t)(k >> 8);
    kb[1] = (uint8_t)k;
    assert(curve448_new_point(&p, &five, 1, ctx) == 0);
    assert(curve448_scalar(p, kb, 2, rnd()) == 0);
    assert(curve448_get_x(out, LEN, p) == 0);
    curve448_free_point(p);
}

/*
 * A ladder step directly: from (nP, (n+1)P) with scaled projective
 * coordinates, it gives (2nP, (2n+1)P).
 */
static void test_ladder_step(const Curve448Context *ctx)
{
    const size_t nw = CURVE448_WORDS;
    Curve448Point *p, *a, *b;
    uint64_t s[CURVE448_WORDS];
    uint8_t five = 5, x1[LEN], x2[LEN];
    EcWs ws;
    unsigned n, i;

    assert(ec_ws_new(&ws, ctx->field) == 0);
    assert(curve448_new_point(&p, &five, 1, ctx) == 0);
    a = NULL;
    b = NULL;

    for (n=1; n<20; n++) {
        uint8_t xn[LEN], xn1[LEN];

        x_of(xn, ctx, n);
        x_of(xn1, ctx, n + 1);
        assert(curve448_new_point(&a, xn, LEN, ctx) == 0);
        assert(curve448_new_point(&b, xn1, LEN, ctx) == 0);

        /* Scale (X:Z) by different factors */
        for (i=0; i<nw; i++)
            s[i] = i == 0 ? rnd() | 1 : 0;
        fe_mul(&ws, a->x, a->x, s);
        fe_mul(&ws, a->z, a->z, s);
        s[0] = rnd() | 1;
        fe_mul(&ws, b->x, b->x, s);
        fe_mul(&ws, b->z, b->z, s);

        curve448_ladder_step(&ws, ctx, a->x, a->z, b->x, b->z, p->x);

        /* Normalize, and compare with the public API */
        assert(fe_inv(&ws, s, a->z, ctx->p_minus_2) == 0);
        fe_mul(&ws, a->x, a->x, s);
        memcpy(a->z, ctx->field->one, nw*8);
        assert(fe_inv(&ws, s, b->z, ctx->p_minus_2) == 0);
        fe_mul(&ws, b->x, b->x, s);
        memcpy(b->z, ctx->field->one, nw*8);

        assert(curve448_get_x(x1, LEN, a) == 0);
        x_of(x2, ctx, 2*n);
        assert(memcmp(x1, x2, LEN) == 0);
        assert(curve448_get_x(x1, LEN, b) == 0);
        x_of(x2, ctx, 2*n + 1);
        assert(memcmp(x1, x2, LEN) == 0);

        curve448_free_point(a);
        curve448_free_point(b);
    }

    /* From the point at infinity: (1:0) doubled is (1:0)-like (Z = 0) */
    assert(curve448_new_point(&a, NULL, 0, ctx) == 0);
    assert(curve448_new_point(&b, &five, 1, ctx) == 0);
    curve448_ladder_step(&ws, ctx, a->x, a->z, b->x, b->z, p->x);
    assert(words_is_zero(a->z, nw));
    curve448_free_point(a);
    curve448_free_point(b);

    curve448_free_point(p);
    ec_ws_free(&ws);
}

/* The ladder directly: the result does not depend on the seed */
static void test_ladder(const Curve448Context *ctx)
{
    Curve448Point *p, *q;
    uint8_t k[LEN], five = 5, x1[LEN], x2[LEN];
    EcWs ws;
    unsigned t, i;

    assert(ec_ws_new(&ws, ctx->field) == 0);
    for (t=0; t<5; t++) {
        for (i=0; i<LEN; i++)
            k[i] = (uint8_t)rnd();
        assert(curve448_new_point(&p, &five, 1, ctx) == 0);
        assert(curve448_new_point(&q, &five, 1, ctx) == 0);
        assert(curve448_ladder(&ws, ctx, p, k, LEN, rnd()) == 0);
        assert(curve448_ladder(&ws, ctx, q, k, LEN, rnd()) == 0);
        assert(curve448_get_x(x1, LEN, p) == 0);
        assert(curve448_get_x(x2, LEN, q) == 0);
        assert(memcmp(x1, x2, LEN) == 0);
        /* Z is 1 */
        assert(memcmp(p->z, ctx->field->one, CURVE448_WORDS*8) == 0);
        curve448_free_point(p);
        curve448_free_point(q);
    }
    ec_ws_free(&ws);
}

static void test_points(const Curve448Context *ctx)
{
    uint8_t x[LEN], out[LEN], k[LEN];
    Curve448Point *p, *q, *pai;
    Curve448Context *ctx2;

    memset(x, 0, LEN);
    x[LEN - 1] = 5;

    assert(curve448_new_point(NULL, x, LEN, ctx) == ERR_NULL);
    assert(curve448_new_point(&p, x, LEN, NULL) == ERR_NULL);
    assert(curve448_new_point(&p, x, LEN + 1, ctx) == ERR_VALUE);

    /* The point at infinity */
    assert(curve448_new_point(&pai, NULL, 0, ctx) == 0);
    assert(curve448_get_x(out, LEN, pai) == ERR_EC_PAI);
    memset(k, 0x55, LEN);
    assert(curve448_scalar(pai, k, LEN, rnd()) == 0);
    assert(curve448_get_x(out, LEN, pai) == ERR_EC_PAI);

    /* get_x */
    assert(curve448_new_point(&p, x, LEN, ctx) == 0);
    assert(curve448_get_x(out, LEN, p) == 0);
    assert(memcmp(out, x, LEN) == 0);
    assert(curve448_get_x(out, LEN - 1, p) == ERR_MODULUS);
    assert(curve448_get_x(NULL, LEN, p) == ERR_NULL);

    /* Shorter input, and u >= p (reduced: p + 5 is 5) */
    assert(curve448_new_point(&q, (const uint8_t*)"\x05", 1, ctx) == 0);
    assert(curve448_cmp(p, q) == 0);
    curve448_free_point(q);
    /* p + 5 = 2^448 - 2^224 + 4: ff..ff (28 bytes) 00..00 (27 bytes) 04 */
    memset(out, 0xFF, 28);
    memset(out + 28, 0, 28);
    out[LEN - 1] = 0x04;
    assert(curve448_new_point(&q, out, LEN, ctx) == 0);
    assert(curve448_cmp(p, q) == 0);
    curve448_free_point(q);

    /* cmp, clone */
    assert(curve448_clone(&q, p) == 0);
    assert(curve448_cmp(p, q) == 0);
    assert(curve448_cmp(p, pai) == ERR_VALUE);
    assert(curve448_cmp(pai, pai) == 0);

    /* 4n * P = infinity for a point of the curve (order of the group) */
    {
        uint8_t four_n[LEN] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD,
            0xF3, 0x28, 0x8F, 0xA7, 0x11, 0x3B, 0x6D, 0x26, 0xBB, 0x58, 0xDA, 0x40, 0x85, 0xB3,
            0x09, 0xCA, 0x37, 0x16, 0x3D, 0x54, 0x8D, 0xE3, 0x0A, 0x4A, 0xAD, 0x61, 0x13, 0xCC
        };

        assert(curve448_scalar(q, four_n, LEN, rnd()) == 0);
        assert(curve448_get_x(out, LEN, q) == ERR_EC_PAI);
    }

    /* Points of another context */
    assert(curve448_new_context(&ctx2) == 0);
    curve448_free_point(q);
    assert(curve448_new_point(&q, x, LEN, ctx2) == 0);
    assert(curve448_cmp(p, q) == ERR_EC_CURVE);
    curve448_free_context(ctx2);
    curve448_free_point(q);                     /* after its context */

    assert(curve448_scalar(NULL, k, LEN, 0) == ERR_NULL);
    assert(curve448_scalar(p, NULL, LEN, 0) == ERR_NULL);
    assert(curve448_cmp(NULL, p) == ERR_NULL);

    curve448_free_point(p);
    curve448_free_point(pai);
    curve448_free_point(NULL);
}

int main(void)
{
    Curve448Context *ctx;

#if defined(TEST_BMI2_ADX)
    if (!have_bmi2_adx()) {
        if (getenv("NAT_REQUIRE_BMI2_ADX")) {
            printf("BMI2 and ADX are required but not available\n");
            return 1;
        }
        printf("Skipping: the CPU does not support BMI2 and ADX\n");
        return 0;
    }
#endif

    assert(curve448_new_context(NULL) == ERR_NULL);
    assert(curve448_new_context(&ctx) == 0);
    test_vectors(ctx);
    test_iterations(ctx);
    test_dh(ctx);
    test_points(ctx);
    test_ladder_step(ctx);
    test_ladder(ctx);
    curve448_free_context(ctx);
    curve448_free_context(NULL);
    return 0;
}
