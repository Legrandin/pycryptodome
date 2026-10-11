/*
 * Constant-time check of Ed25519 (ed25519.c and mod25519.c), with Valgrind
 * memcheck, like test_ec_nat_ct.c.
 *
 * The secret inputs (the scalar, the random seed and, for the variable
 * base, the input point itself) are marked as undefined memory:
 * Valgrind then reports every conditional jump and every memory access
 * that depends on them. Intended leaks go through ct_declassify().
 * The affine coordinates of the results are computed too.
 *
 * Build with -DNAT_CTGRIND and run under:
 *     valgrind --error-exitcode=1 ./test_ed25519_ct
 * The results are not checked here (see test_ed25519.c).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"
#include "ed25519.h"

#define SECRET(p, len)  VALGRIND_MAKE_MEM_UNDEFINED(p, len)

/* The generator, big-endian */
static const uint8_t gx[32] = {
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a };
static const uint8_t gy[32] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58 };

static uint64_t state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

/* The generator; if secret, its coordinates are marked as such once validated */
static Point *new_g(int secret)
{
    Point *p;

    assert(ed25519_new_point(&p, gx, gy, 32, NULL) == 0);
    if (secret)
        SECRET(p, sizeof *p);
    return p;
}

static void mul(Point *p, size_t len)
{
    uint8_t k[64], x[32], y[32];
    uint64_t seed = rnd();
    size_t i;

    for (i=0; i<len; i++)
        k[i] = (uint8_t)rnd();
    SECRET(k, len);
    SECRET(&seed, sizeof seed);
    assert(ed25519_scalar(p, k, len, seed) == 0);
    assert(ed25519_get_xy(x, y, 32, p) == 0);
}

int main(void)
{
    Point *g, *r;
    unsigned i;

    for (i=0; i<2; i++) {
        /* Fixed base (signatures, key generation) */
        g = new_g(0);
        mul(g, 32);
        mul(g, 64);

        /* Variable base, secret */
        r = new_g(1);
        mul(r, 32);

        assert(ed25519_add(r, g) == 0);
        assert(ed25519_double(r) == 0);
        assert(ed25519_neg(r) == 0);
        (void)ed25519_cmp(r, g);    /* only the result leaks */

        ed25519_free_point(g);
        ed25519_free_point(r);
    }
    return 0;
}
