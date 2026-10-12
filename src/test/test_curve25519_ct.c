/*
 * Constant-time check of X25519 (curve25519.c and mod25519.c), with Valgrind
 * memcheck, like test_ec_nat_ct.c.
 *
 * The secret inputs (the scalar, the random seed and, in some runs, the
 * u-coordinate) are marked as undefined memory: Valgrind then reports
 * every conditional jump and every memory access that depends on them.
 * Intended leaks go through ct_declassify().
 *
 * Build with -DNAT_CTGRIND and run under:
 *     valgrind --error-exitcode=1 ./test_curve25519_ct
 * The results are not checked here (see test_curve25519.c).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"
#include "curve25519.h"

#define SECRET(p, len)  VALGRIND_MAKE_MEM_UNDEFINED(p, len)

static uint64_t state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

/* Secret scalar, public and secret u-coordinate */
int main(void)
{
    Point *p, *pai;
    uint8_t u[32], k[32], x[32];
    uint64_t seed;
    unsigned i, j;

    assert(curve25519_new_point(&pai, NULL, 0, NULL) == 0);
    for (i=0; i<4; i++) {
        for (j=0; j<32; j++) {
            u[j] = (uint8_t)rnd();
            k[j] = (uint8_t)rnd();
        }
        if (i == 0) {
            memset(u, 0, 32);
            u[31] = 9;
        }
        if (i >= 2)
            SECRET(u, 32);
        seed = rnd();
        SECRET(k, 32);
        SECRET(&seed, sizeof seed);
        assert(curve25519_new_point(&p, u, 32, NULL) == 0);
        assert(curve25519_scalar(p, k, 32, seed) == 0);
        /* Only the fact that the result is the point at infinity leaks */
        (void)curve25519_get_x(x, 32, p);
        (void)curve25519_cmp(p, pai);
        curve25519_free_point(p);
    }
    curve25519_free_point(pai);
    return 0;
}
