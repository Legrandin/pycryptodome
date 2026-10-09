#include <assert.h>
#include <string.h>
#include "common.h"
#include "nat.h"
#include "nat_ct.h"

static Nat *make(size_t nw, const uint64_t *words, size_t len)
{
    Nat *x;
    size_t i;
    int res;

    res = nat_new(&x, nw);
    assert(res == 0);
    for (i=0; i<len && i<nw; i++)
        x->w[i] = words[i];
    return x;
}

static Nat *make1(size_t nw, uint64_t v)
{
    return make(nw, &v, 1);
}

void test_ct_helpers(void)
{
    assert(ct_nz(0) == 0);
    assert(ct_nz(1) == 1);
    assert(ct_nz(UINT64_MAX) == 1);
    assert(ct_eq(5, 5) == 1);
    assert(ct_eq(5, 6) == 0);
    assert(ct_lt(1, 2) == 1);
    assert(ct_lt(2, 1) == 0);
    assert(ct_lt(2, 2) == 0);
    assert(ct_lt(0, UINT64_MAX) == 1);
    assert(ct_lt(UINT64_MAX, 0) == 0);
    assert(ct_mask(1) == UINT64_MAX);
    assert(ct_mask(0) == 0);
    assert(ct_select(UINT64_MAX, 3, 4) == 3);
    assert(ct_select(0, 3, 4) == 4);
    assert(ct_bitlen64(0) == 0);
    assert(ct_bitlen64(1) == 1);
    assert(ct_bitlen64(UINT64_MAX) == 64);
    assert(ct_bitlen64((uint64_t)1 << 40) == 41);
    assert(ct_ctz64(0) == 64);
    assert(ct_ctz64(1) == 0);
    assert(ct_ctz64((uint64_t)1 << 63) == 63);
}

void test_ct_add_sub(void)
{
    uint64_t c, r;

    r = ct_add(UINT64_MAX, 1, 0, &c);
    assert(r == 0 && c == 1);
    r = ct_add(UINT64_MAX, UINT64_MAX, 1, &c);
    assert(r == UINT64_MAX && c == 1);
    r = ct_add(UINT64_MAX, 0, 1, &c);
    assert(r == 0 && c == 1);
    r = ct_add(1, 2, 0, &c);
    assert(r == 3 && c == 0);

    r = ct_sub(0, 1, 0, &c);
    assert(r == UINT64_MAX && c == 1);
    r = ct_sub(0, 0, 1, &c);
    assert(r == UINT64_MAX && c == 1);
    r = ct_sub(5, 5, 0, &c);
    assert(r == 0 && c == 0);
    r = ct_sub(0, UINT64_MAX, 1, &c);
    assert(r == 0 && c == 1);

    r = ct_mac(UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, &c);
    assert(r == UINT64_MAX && c == UINT64_MAX);
}

void test_new_and_free(void)
{
    Nat *x;

    assert(nat_new(NULL, 1) == ERR_NULL);
    assert(nat_new(&x, 0) == ERR_VALUE);
    assert(nat_new(&x, NAT_MAX_WORDS + 1) == ERR_VALUE);
    assert(nat_new(&x, 3) == 0);
    assert(x->nw == 3);
    assert(x->w[0] == 0 && x->w[1] == 0 && x->w[2] == 0);
    nat_free(x);
    nat_free(NULL);
}

void test_bytes(void)
{
    const uint8_t in[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    uint8_t out[10];
    Nat *x, *y;

    nat_new(&x, 2);
    assert(nat_from_bytes(x, in, 9, 0) == 0);
    assert(x->w[0] == 0x0203040506070809ULL);
    assert(x->w[1] == 1);
    assert(nat_from_bytes(x, in, 9, 1) == 0);
    assert(x->w[0] == 0x0807060504030201ULL);
    assert(x->w[1] == 9);

    memset(out, 0xAA, sizeof out);
    assert(nat_to_bytes(out, 10, x, 1) == 0);
    assert(memcmp(out, in, 9) == 0 && out[9] == 0);
    assert(nat_to_bytes(out, 8, x, 1) == ERR_VALUE);

    /* Too long for a single word */
    nat_new(&y, 1);
    assert(nat_from_bytes(y, in, 9, 0) == ERR_VALUE);
    /* Leading zeros are fine */
    {
        const uint8_t padded[9] = { 0, 2, 3, 4, 5, 6, 7, 8, 9 };
        assert(nat_from_bytes(y, padded, 9, 0) == 0);
        assert(y->w[0] == 0x0203040506070809ULL);
    }

    nat_free(x);
    nat_free(y);
}

void test_bit_length_and_cmp(void)
{
    const uint64_t w1[3] = { 0, 0, 1 };
    const uint64_t w2[3] = { UINT64_MAX, UINT64_MAX, 0 };
    Nat *a, *b, *z;

    a = make(3, w1, 3);
    b = make(2, w2, 2);
    z = make1(4, 0);

    assert(nat_bit_length(a) == 129);
    assert(nat_bit_length(b) == 128);
    assert(nat_bit_length(z) == 0);
    assert(nat_cmp(a, b) == 1);
    assert(nat_cmp(b, a) == -1);
    assert(nat_cmp(a, a) == 0);
    assert(nat_cmp(z, z) == 0);
    assert(nat_is_zero(z) == 1);
    assert(nat_is_zero(a) == 0);
    assert(nat_get_bit(a, 128) == 1);
    assert(nat_get_bit(a, 127) == 0);
    assert(nat_get_bit(a, 1000) == 0);

    nat_free(a);
    nat_free(b);
    nat_free(z);
}

void test_add_sub(void)
{
    const uint64_t w[2] = { UINT64_MAX, UINT64_MAX };
    Nat *a, *one, *out;

    a = make(2, w, 2);
    one = make1(1, 1);
    nat_new(&out, 3);

    /* Carry into a third word */
    assert(nat_add(out, a, one) == 0);
    assert(out->w[0] == 0 && out->w[1] == 0 && out->w[2] == 1);

    /* And back */
    assert(nat_sub(out, out, one) == 0);
    assert(out->w[0] == UINT64_MAX && out->w[1] == UINT64_MAX && out->w[2] == 0);

    /* Negative result */
    assert(nat_sub(out, one, a) == ERR_VALUE);

    /* The borrow is detected also beyond the size of out */
    {
        Nat *small;
        nat_new(&small, 1);
        assert(nat_sub(small, one, a) == ERR_VALUE);
        assert(nat_sub(small, a, one) == 0);
        nat_free(small);
    }

    nat_free(a);
    nat_free(one);
    nat_free(out);
}

void test_mul_and_shift(void)
{
    const uint64_t w[2] = { UINT64_MAX, UINT64_MAX };
    Nat *a, *out, *t;

    a = make(2, w, 2);
    nat_new(&out, 4);
    nat_new(&t, 4);

    /* (2^128 - 1)^2 = 2^256 - 2^129 + 1 */
    assert(nat_mul(out, a, a) == 0);
    assert(out->w[0] == 1 && out->w[1] == 0);
    assert(out->w[2] == UINT64_MAX - 1 && out->w[3] == UINT64_MAX);
    assert(nat_mul(out, out, a) == ERR_VALUE);

    assert(nat_shl(t, a, 65) == 0);
    assert(t->w[0] == 0 && t->w[1] == UINT64_MAX - 1 && t->w[2] == UINT64_MAX && t->w[3] == 1);
    assert(nat_shr(out, t, 65) == 0);
    assert(out->w[0] == UINT64_MAX && out->w[1] == UINT64_MAX && out->w[2] == 0);
    assert(nat_shr(out, t, 64) == 0);
    assert(out->w[0] == UINT64_MAX - 1 && out->w[1] == UINT64_MAX && out->w[2] == 1);

    nat_free(a);
    nat_free(out);
    nat_free(t);
}

void test_divmod(void)
{
    const uint64_t wa[3] = { 7, 0, 5 };
    Nat *a, *b, *q, *r, *z;

    a = make(3, wa, 3);
    b = make1(1, 3);
    z = make1(1, 0);
    nat_new(&q, 3);
    nat_new(&r, 1);

    /* (5*2^128 + 7) = 3 * q + r */
    assert(nat_divmod(q, r, a, b) == 0);
    assert(q->w[0] == 0xAAAAAAAAAAAAAAADULL);
    assert(q->w[1] == 0xAAAAAAAAAAAAAAAAULL);
    assert(q->w[2] == 1);
    assert(r->w[0] == 0);

    assert(nat_divmod(q, r, a, z) == ERR_VALUE);
    assert(nat_divmod(NULL, NULL, a, b) == ERR_NULL);

    assert(nat_mod_small(r, a, 1000003) == 0);
    {
        /* 5*2^128 + 7 mod 1000003, computed with Python */
        assert(r->w[0] == 15137);
    }
    assert(nat_mod_small(r, a, 0) == ERR_VALUE);
    assert(nat_mod_small(r, a, (uint64_t)1 << 32) == ERR_VALUE);

    nat_free(a);
    nat_free(b);
    nat_free(q);
    nat_free(r);
    nat_free(z);
}

void test_modular(void)
{
    Nat *a, *e, *m, *me, *out, *one;

    a = make1(1, 23);
    e = make1(1, 5);
    m = make1(1, 17);
    me = make1(1, 18);
    one = make1(1, 1);
    nat_new(&out, 1);

    assert(nat_powmod(out, a, e, m) == 0);
    assert(out->w[0] == 7);
    assert(nat_powmod(out, a, e, me) == 0);
    assert(out->w[0] == 23*23*23*23*23 % 18);
    assert(nat_powmod(out, a, e, one) == 0);
    assert(out->w[0] == 0);

    assert(nat_invmod(out, a, m) == 0);
    assert(out->w[0] * 23 % 17 == 1);
    assert(nat_invmod(out, e, me) == 0);
    assert(out->w[0] * 5 % 18 == 1);
    assert(nat_invmod(out, me, me) == ERR_VALUE);

    assert(nat_mulmod(out, a, e, m) == 0);
    assert(out->w[0] == 23*5 % 17);

    {
        Nat *x = make1(1, 3), *y = make1(1, 10);
        assert(nat_submod(out, x, y, m) == 0);
        assert(out->w[0] == 10);
        nat_free(x);
        nat_free(y);
    }

    nat_free(a);
    nat_free(e);
    nat_free(m);
    nat_free(me);
    nat_free(one);
    nat_free(out);
}

void test_number_theory(void)
{
    Nat *a, *b, *out;
    const uint64_t big[2] = { 0, 1 };      /* 2^64 */

    a = make1(1, 48);
    b = make(2, big, 2);
    nat_new(&out, 2);

    assert(nat_gcd(out, a, b) == 0);
    assert(out->w[0] == 16 && out->w[1] == 0);

    assert(nat_isqrt(out, b) == 0);
    assert(out->w[0] == (uint64_t)1 << 32);

    {
        Nat *n = make1(1, 21), *k = make1(1, 8);
        assert(nat_jacobi(out, k, n, 0) == 0);
        assert(out->w[0] == 0);         /* (8/21) = -1 */
        assert(nat_jacobi(out, k, n, 1) == 0);
        assert(out->w[0] == 0);         /* (-8/21) = (-1/21)(8/21) = -1 */
        assert(nat_jacobi(out, n, k, 0) == ERR_VALUE);
        nat_free(n);
        nat_free(k);
    }

    {
        /* 2^61 - 1 is prime, 561 is a Carmichael number */
        Nat *p = make1(1, ((uint64_t)1 << 61) - 1), *c = make1(1, 561), *base = make1(1, 2);
        assert(nat_miller_rabin(out, p, base) == 0);
        assert(out->w[0] == 1);
        assert(nat_miller_rabin(out, c, base) == 0);
        assert(out->w[0] == 0);
        /* D = 17 is the first in 5, -7, 9, ... with (D/p) = -1 */
        assert(nat_lucas(out, p, 17, 0) == 0);
        assert(out->w[0] == 1);
        nat_free(p);
        nat_free(c);
        nat_free(base);
    }

    nat_free(a);
    nat_free(b);
    nat_free(out);
}

int main(void)
{
    test_ct_helpers();
    test_ct_add_sub();
    test_new_and_free();
    test_bytes();
    test_bit_length_and_cmp();
    test_add_sub();
    test_mul_and_shift();
    test_divmod();
    test_modular();
    test_number_theory();
    return 0;
}
