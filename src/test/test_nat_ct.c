/*
 * Constant-time check of the nat library ("ctgrind").
 *
 * Secret inputs are marked as undefined memory: Valgrind memcheck then
 * reports every conditional jump and every memory access that depends
 * on them. Intended leaks go through ct_declassify() in the library.
 *
 * Build with -DNAT_CTGRIND and run under:
 *     valgrind --error-exitcode=1 ./test_nat_ct
 * The results are not checked here (see test_nat.c).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"
#include "nat.h"

static uint64_t state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

static Nat *secret(size_t nw, int odd)
{
    Nat *x;
    size_t i;

    assert(nat_new(&x, nw) == 0);
    for (i=0; i<nw; i++)
        x->w[i] = rnd();
    x->w[nw-1] >>= 1;           /* a bit smaller than the maximum */
    if (odd)
        x->w[0] |= 1;
    VALGRIND_MAKE_MEM_UNDEFINED(x->w, nw*sizeof(uint64_t));
    return x;
}

static Nat *zeros(size_t nw)
{
    Nat *x;

    assert(nat_new(&x, nw) == 0);
    return x;
}

static void run(size_t nw)
{
    Nat *a, *b, *c, *m_odd, *m_even, *e, *n, *base, *out, *out2, *q, *small;
    uint8_t buf[8*64];
    int res;

    a = secret(nw, 1);
    b = secret(nw, 0);
    c = secret(nw, 0);
    e = secret(nw, 0);
    m_odd = secret(nw, 1);
    m_even = secret(nw, 0);
    m_even->w[0] &= ~(uint64_t)1;
    VALGRIND_MAKE_MEM_UNDEFINED(m_even->w, sizeof(uint64_t));
    n = secret(nw, 1);
    base = secret(1, 0);
    out = zeros(2*nw + 1);
    out2 = zeros(2*nw + 1);
    q = zeros(2*nw + 1);
    small = zeros(1);

    /* Make m_even surely even, and small "a" values secret too */
    m_even->w[0] = rnd() << 1;
    VALGRIND_MAKE_MEM_UNDEFINED(m_even->w, sizeof(uint64_t));
    base->w[0] = 2 + (rnd() >> 8);
    VALGRIND_MAKE_MEM_UNDEFINED(base->w, sizeof(uint64_t));

    /* Conversions */
    nat_to_bytes(buf, 8*nw, a, 0);
    nat_from_bytes(out, buf, 8*nw, 1);
    nat_copy(out, a);
    (void)nat_bit_length(a);
    (void)nat_is_zero(a);
    (void)nat_is_odd(a);
    (void)nat_cmp(a, b);
    (void)nat_get_bit(a, 5);

    /* Arithmetic */
    nat_add(out, a, b);
    nat_sub(out, a, b);
    nat_mul(out, a, b);
    nat_muladd(out2, c, a, b);
    nat_and(out, a, b);
    nat_or(out, a, b);
    nat_shl(out, a, 70);
    nat_shr(out, a, 70);

    /* Division */
    nat_divmod(q, out, a, b);
    nat_mod_small(small, a, 1000003);

    /* Modular arithmetic */
    nat_mulmod(out, a, b, m_odd);
    nat_powmod(out, a, e, 64*nw, m_odd);
    nat_powmod(out, a, e, 64*nw, m_even);
    res = nat_invmod(out, a, m_odd);
    (void)res;
    res = nat_invmod(out, a, m_even);
    (void)res;

    /* Number theory */
    nat_gcd(out, a, b);
    nat_jacobi(small, a, n, 0);
    nat_jacobi(small, a, n, 1);
    nat_isqrt(out, a);
    nat_miller_rabin(small, n, base);
    nat_lucas(small, n, 17, 0);

    nat_free(a);
    nat_free(b);
    nat_free(c);
    nat_free(e);
    nat_free(m_odd);
    nat_free(m_even);
    nat_free(n);
    nat_free(base);
    nat_free(out);
    nat_free(out2);
    nat_free(q);
    nat_free(small);
}

int main(void)
{
    size_t nw;

    for (nw=1; nw<=4; nw++)
        run(nw);
    run(16);
    return 0;
}
