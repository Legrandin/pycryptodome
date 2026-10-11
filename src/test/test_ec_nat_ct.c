/*
 * Constant-time check of the elliptic curves on the nat library
 * (ec_nat.c, ed448.c, curve448.c), with Valgrind memcheck, like
 * test_nat_ct.c.
 *
 * The secret inputs (the scalar, the random seed and, for the variable
 * base, the input point itself) are marked as undefined memory:
 * Valgrind then reports every conditional jump and every memory access
 * that depends on them. Intended leaks go through ct_declassify().
 * The affine coordinates of the results are computed too (as for an
 * ECDH shared secret).
 *
 * Build with -DNAT_CTGRIND and run under:
 *     valgrind --error-exitcode=1 ./test_ec_nat_ct
 * The results are not checked here (see test_ec_nat.c).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"
#include "nat.h"
#include "ec_nat.h"
#include "ed448.h"
#include "curve448.h"

#if defined(TEST_BMI2_ADX)
#include <stdio.h>
#include <stdlib.h>
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

typedef struct {
    const char *name;
    size_t len;
    const char *p, *b, *n, *gx, *gy;
    const char *qx, *qy;            /* another point */
} Curve;

static const Curve curves[] = {
    { "P-192", 24,
      "fffffffffffffffffffffffffffffffeffffffffffffffff",
      "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
      "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
      "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
      "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
      "adfa92060496128ce8d4b2d8c2f3e09a9531f874545f2db8",
      "4c605b57afc597cda5ba8ab6f548d56b1b4a3ec8101b442b" },
    { "P-224", 28,
      "ffffffffffffffffffffffffffffffff000000000000000000000001",
      "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
      "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
      "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
      "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
      "e9a1a9b8f8e9e3deca8ce0ac06f0c8a63c7afa10c4dece9824b10177",
      "4782540c2f6dc3957210872f842a67c3bac23954915d80806a6055c2" },
    { "P-256", 32,
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
      "6a0fde29d4ef0772d3069f6faca31d69b5d1ccd5ee213d0f10215b4c65290035",
      "686e4766719349fa223484a8e30d4905aed06ef8505cc9c4d85e1d3057dff4b8" },
    { "P-384", 48,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
      "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
      "8fbbe97c200d67ac8f03c177fb48f08f4f0735814711e6a29be23a975a9776eaedd230a50948a29a78d0eec987ea707e",
      "1e94b0822b477100f57f17110d466fbb519625bbe1e4e42877308fe382d795477eb66747a209949afafc908b5351a598" },
    { "P-521", 66,
      "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
      "018c993bccac4691f057a142f6f63cd53ce0c9c389a3b711af11b3196328b499edf795760244a93da5730a60a42d080f7fcfb415fec9ad287a3b74b5ae338e5397f0",
      "0150051f03fdb26e525063e686f842182f3ff094235176de4716bfeab17ea238be9e39879f824ebfc3e7325531177af6951be687309bdcfaf8b396bbdaf4d76e9ac0" },
};

#define MAX_LEN 80

#define SECRET(p, len)  VALGRIND_MAKE_MEM_UNDEFINED(p, len)
#define PUBLIC(p, len)  VALGRIND_MAKE_MEM_DEFINED(p, len)

static uint64_t state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

static void from_hex(uint8_t *out, size_t len, const char *hex)
{
    size_t digits = strlen(hex), i;

    memset(out, 0, len);
    for (i=0; i<digits; i++) {
        char ch = hex[digits - 1 - i];
        unsigned v = (ch >= '0' && ch <= '9') ? (unsigned)(ch - '0') : (unsigned)(ch - 'a' + 10);

        out[len - 1 - i/2] |= (uint8_t)(v << (4*(i % 2)));
    }
}

static EcPointN *new_point(const EcCurve *c, const char *x, const char *y, int secret)
{
    uint8_t xb[MAX_LEN], yb[MAX_LEN];
    EcPointN *p;

    from_hex(xb, c->len, x);
    from_hex(yb, c->len, y);
    if (secret) {
        SECRET(xb, c->len);
        SECRET(yb, c->len);
    }
    assert(ec_nat_new_point(&p, xb, yb, c->len, c) == 0);
    return p;
}

/* The affine coordinates (secret) */
static void get_xy(const EcPointN *p)
{
    uint8_t x[MAX_LEN], y[MAX_LEN];

    assert(ec_nat_get_xy(x, y, p->curve->len, p) == 0);
}

static void scalar(EcPointN *p, size_t len)
{
    uint8_t k[MAX_LEN + 8];
    uint64_t seed = rnd();
    size_t i;

    for (i=0; i<len; i++)
        k[i] = (uint8_t)rnd();
    SECRET(k, len);
    SECRET(&seed, sizeof seed);
    assert(ec_nat_scalar(p, k, len, seed) == 0);
    get_xy(p);
}

static void run(const Curve *tc)
{
    uint8_t p[MAX_LEN], b[MAX_LEN], n[MAX_LEN], gx[MAX_LEN], gy[MAX_LEN];
    size_t len = tc->len;
    EcCurve *c;
    EcPointN *g, *q, *r;
    unsigned t;

    from_hex(p, len, tc->p);
    from_hex(b, len, tc->b);
    from_hex(n, len, tc->n);
    from_hex(gx, len, tc->gx);
    from_hex(gy, len, tc->gy);
    assert(ec_nat_new_curve(&c, p, b, n, gx, gy, len) == 0);

    for (t=0; t<2; t++) {
        /* Fixed base (k*G), as for a key generation or a signature */
        g = new_point(c, tc->gx, tc->gy, 0);
        scalar(g, len);
        scalar(g, len + 8);         /* longer than the order */

        /* Variable base (k*Q), as for ECDH: public, and also secret Q */
        q = new_point(c, tc->qx, tc->qy, 0);
        scalar(q, len);
        r = new_point(c, tc->qx, tc->qy, 1);
        scalar(r, len);

        /* Operations on secret points */
        assert(ec_nat_add(r, q) == 0);
        assert(ec_nat_add(r, r) == 0);
        assert(ec_nat_double(r) == 0);
        assert(ec_nat_neg(r) == 0);
        get_xy(r);
        (void)ec_nat_cmp(r, q);     /* only the result leaks */

        ec_nat_free_point(g);
        ec_nat_free_point(q);
        ec_nat_free_point(r);
    }

    ec_nat_free_curve(c);
}

/* Ed448: the generator, and a point with a component of order 4 */
static const char *ed_gx = "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e";
static const char *ed_gy = "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14";

static PointEd448 *ed448_point(const Ed448Context *ctx, const char *x, const char *y, int secret)
{
    uint8_t xb[56], yb[56];
    PointEd448 *p;

    from_hex(xb, 56, x);
    from_hex(yb, 56, y);
    if (secret) {
        SECRET(xb, 56);
        SECRET(yb, 56);
    }
    assert(ed448_new_point(&p, xb, yb, 56, ctx) == 0);
    return p;
}

static void ed448_mul(PointEd448 *p, size_t len)
{
    uint8_t k[64], x[56], y[56];
    uint64_t seed = rnd();
    size_t i;

    for (i=0; i<len; i++)
        k[i] = (uint8_t)rnd();
    SECRET(k, len);
    SECRET(&seed, sizeof seed);
    assert(ed448_scalar(p, k, len, seed) == 0);
    assert(ed448_get_xy(x, y, 56, p) == 0);
}

static void run_ed448(void)
{
    Ed448Context *ctx;
    PointEd448 *g, *q, *t, *r;
    unsigned i;

    assert(ed448_new_context(&ctx) == 0);
    for (i=0; i<2; i++) {
        /* Fixed base (signatures, key generation) */
        g = ed448_point(ctx, ed_gx, ed_gy, 0);
        ed448_mul(g, 57);
        ed448_mul(g, 64);

        /* Variable base: public (verification), secret; with a point of order 4 */
        q = ed448_point(ctx, ed_gx, ed_gy, 0);
        ed448_mul(q, 57);
        r = ed448_point(ctx, ed_gx, ed_gy, 1);
        ed448_mul(r, 57);
        t = ed448_point(ctx, "1", "0", 0);
        assert(ed448_add(t, r) == 0);
        ed448_mul(t, 57);

        assert(ed448_add(r, q) == 0);
        assert(ed448_double(r) == 0);
        assert(ed448_neg(r) == 0);
        (void)ed448_cmp(r, q);      /* only the result leaks */

        ed448_free_point(g);
        ed448_free_point(q);
        ed448_free_point(t);
        ed448_free_point(r);
    }
    ed448_free_context(ctx);
}

/* X448: secret scalar, public and secret u-coordinate */
static void run_x448(void)
{
    Curve448Context *ctx;
    Curve448Point *p;
    uint8_t u[56], k[56], x[56];
    uint64_t seed;
    unsigned i, j;

    assert(curve448_new_context(&ctx) == 0);
    for (i=0; i<4; i++) {
        for (j=0; j<56; j++) {
            u[j] = (uint8_t)rnd();
            k[j] = (uint8_t)rnd();
        }
        if (i == 0) {
            memset(u, 0, 56);
            u[55] = 5;
        }
        if (i >= 2)
            SECRET(u, 56);
        seed = rnd();
        SECRET(k, 56);
        SECRET(&seed, sizeof seed);
        assert(curve448_new_point(&p, u, 56, ctx) == 0);
        assert(curve448_scalar(p, k, 56, seed) == 0);
        /* Only the fact that the result is the point at infinity leaks */
        (void)curve448_get_x(x, 56, p);
        curve448_free_point(p);
    }
    curve448_free_context(ctx);
}

int main(void)
{
    size_t i;

#if defined(TEST_BMI2_ADX)
    /* Valgrind does not report ADX in CPUID, but it can run it */
    if (!have_bmi2_adx() && !RUNNING_ON_VALGRIND) {
        printf("Skipping: the CPU does not support BMI2 and ADX\n");
        return 0;
    }
#endif

    for (i=0; i<sizeof curves / sizeof curves[0]; i++)
        run(&curves[i]);
    run_ed448();
    run_x448();
    return 0;
}
