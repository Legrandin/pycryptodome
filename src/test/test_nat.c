#include <assert.h>
#include <string.h>
#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/* Private functions (they are not static when STATIC is defined as empty) */
void wipe(void *p, size_t len);
void words_shr_public(uint64_t *out, const uint64_t *x, size_t s, size_t nw);
void words_shl_public(uint64_t *out, const uint64_t *x, size_t s, size_t nw);
void nat_to_words(uint64_t *out, const Nat *a, size_t nw);
void words_to_nat(Nat *out, const uint64_t *x, size_t nw);
int mulmod_words(uint64_t *out, const uint64_t *x, const uint64_t *y, const Nat *m, Nat *prod);
uint64_t div128_ct(uint64_t hi, uint64_t lo, uint64_t d);
uint64_t reciprocal_ct(uint64_t d);
uint64_t div128_preinv_ct(uint64_t hi, uint64_t lo, uint64_t d, uint64_t recip);
int inv_odd_simple(uint64_t *out, const uint64_t *a, const uint64_t *n, size_t nw);
void lin_comb(uint64_t *out, const uint64_t *x, const uint64_t *y, int64_t f, int64_t g, size_t nw);
void shr_signed(uint64_t *x, size_t nw);
void cond_negate(uint64_t mask, uint64_t *x, size_t nw);
void approximations(uint64_t *a_approx, uint64_t *b_approx, const uint64_t *a, const uint64_t *b, size_t nw);
void mod_lin_comb(uint64_t *x, const uint64_t *u, const uint64_t *v, int64_t f, int64_t g,
                  const uint64_t *n, uint64_t n0inv, uint64_t *t, uint64_t *kn, size_t nw);
uint64_t addmul_row(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw);

#if defined(TEST_BMI2_ADX)
#include <stdio.h>
#include <cpuid.h>

/* The build for BMI2 and ADX can only be tested on a CPU that has both */
static int have_bmi2_adx(void)
{
    unsigned eax, ebx, ecx, edx;

    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1U << 8)) && (ebx & (1U << 19));
}
#endif

static uint64_t rnd_state = 0x9E3779B97F4A7C15ULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return rnd_state;
}

#define MAX64 UINT64_MAX

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

    assert(nat_powmod(out, a, e, 64, m) == 0);
    assert(out->w[0] == 7);
    /* The same, with the tightest bound on e = 5 (3 bits) */
    assert(nat_powmod(out, a, e, 3, m) == 0);
    assert(out->w[0] == 7);
    assert(nat_powmod(out, a, e, 0, m) == 0);       /* e is taken as 0 */
    assert(out->w[0] == 1);
    assert(nat_powmod(out, a, e, 64, me) == 0);
    assert(out->w[0] == 23*23*23*23*23 % 18);
    assert(nat_powmod(out, a, e, 64, one) == 0);
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

void test_ct_misc(void)
{
    assert(ct_z(0) == 1);
    assert(ct_z(1) == 0);
    assert(ct_z(MAX64) == 0);
    assert(ct_barrier(0x1234) == 0x1234);
    assert(ct_declassify(0x5678) == 0x5678);
}

void test_memory_helpers(void)
{
    uint64_t *w;
    uint8_t buf[16];
    Nat *x;
    size_t i;

    assert(nat_words_alloc(0) == NULL);
    w = nat_words_alloc(5);
    assert(w != NULL);
    for (i=0; i<5; i++)
        assert(w[i] == 0);
    nat_words_free(w, 5);
    nat_words_free(NULL, 5);

    x = nat_alloc(3);
    assert(x != NULL && x->nw == 3);
    assert(nat_alloc(0) == NULL);
    x->w[1] = 7;
    assert(nat_word(x, 1) == 7);
    assert(nat_word(x, 3) == 0);
    assert(nat_word(x, 1000) == 0);
    nat_free(x);

    memset(buf, 0xAA, sizeof buf);
    wipe(buf, 15);
    for (i=0; i<15; i++)
        assert(buf[i] == 0);
    assert(buf[15] == 0xAA);
}

void test_copy_and_conversions(void)
{
    const uint64_t w3[3] = { 1, 2, 3 };
    uint64_t words[4];
    uint8_t out[24];
    Nat *a, *b;

    a = make(3, w3, 3);

    /* Truncation and zero extension */
    nat_new(&b, 2);
    assert(nat_copy(b, a) == 0);
    assert(b->w[0] == 1 && b->w[1] == 2);
    nat_free(b);
    nat_new(&b, 4);
    b->w[3] = MAX64;
    assert(nat_copy(b, a) == 0);
    assert(b->w[0] == 1 && b->w[1] == 2 && b->w[2] == 3 && b->w[3] == 0);

    assert(nat_from_uint64(b, 99) == 0);
    assert(b->w[0] == 99 && b->w[1] == 0 && b->w[2] == 0 && b->w[3] == 0);
    assert(nat_is_odd(b) == 1);
    assert(nat_from_uint64(b, 98) == 0);
    assert(nat_is_odd(b) == 0);

    /* Big endian, with zero padding */
    assert(nat_to_bytes(out, 24, a, 0) == 0);
    assert(out[23] == 1 && out[15] == 2 && out[7] == 3 && out[0] == 0);
    assert(nat_to_bytes(out, 17, a, 0) == 0);
    assert(out[0] == 3 && out[16] == 1);
    assert(nat_to_bytes(out, 16, a, 0) == ERR_VALUE);

    nat_to_words(words, a, 4);
    assert(words[0] == 1 && words[1] == 2 && words[2] == 3 && words[3] == 0);
    nat_to_words(words, a, 2);
    assert(words[0] == 1 && words[1] == 2);

    words[0] = 5; words[1] = 6;
    words_to_nat(b, words, 2);
    assert(b->w[0] == 5 && b->w[1] == 6 && b->w[2] == 0 && b->w[3] == 0);

    nat_free(a);
    nat_free(b);
}

void test_words_compare_select(void)
{
    uint64_t x[2] = { 5, 1 };
    uint64_t y[2] = { 7, 0 };
    uint64_t z[2] = { 0, 0 };
    uint64_t out[2];

    assert(words_is_zero(z, 2) == 1);
    assert(words_is_zero(x, 2) == 0);
    assert(words_eq(x, x, 2) == 1);
    assert(words_eq(x, y, 2) == 0);
    /* x = 2^64 + 5 > y = 7: the high word decides */
    assert(words_lt(y, x, 2) == 1);
    assert(words_lt(x, y, 2) == 0);
    assert(words_lt(x, x, 2) == 0);

    words_select(out, MAX64, x, y, 2);
    assert(out[0] == 5 && out[1] == 1);
    words_select(out, 0, x, y, 2);
    assert(out[0] == 7 && out[1] == 0);

    words_cswap(0, x, y, 2);
    assert(x[0] == 5 && y[0] == 7);
    words_cswap(MAX64, x, y, 2);
    assert(x[0] == 7 && x[1] == 0 && y[0] == 5 && y[1] == 1);
}

void test_words_add_sub(void)
{
    uint64_t a[2] = { MAX64, MAX64 };
    uint64_t one[2] = { 1, 0 };
    uint64_t out[2];

    assert(words_add(out, a, one, 2) == 1);
    assert(out[0] == 0 && out[1] == 0);
    assert(words_add(out, one, one, 2) == 0);
    assert(out[0] == 2 && out[1] == 0);

    assert(words_sub(out, one, a, 2) == 1);
    assert(out[0] == 2 && out[1] == 0);
    assert(words_sub(out, a, one, 2) == 0);
    assert(out[0] == MAX64 - 1 && out[1] == MAX64);

    /* In place, with masks */
    out[0] = 0; out[1] = 1;
    assert(words_cond_sub(0, out, one, 2) == 0);
    assert(out[0] == 0 && out[1] == 1);
    assert(words_cond_sub(MAX64, out, one, 2) == 0);
    assert(out[0] == MAX64 && out[1] == 0);
    assert(words_cond_add(0, out, one, 2) == 0);
    assert(out[0] == MAX64 && out[1] == 0);
    assert(words_cond_add(MAX64, out, one, 2) == 0);
    assert(out[0] == 0 && out[1] == 1);
    out[0] = MAX64; out[1] = MAX64;
    assert(words_cond_add(MAX64, out, one, 2) == 1);
    assert(out[0] == 0 && out[1] == 0);
}

void test_words_shifts(void)
{
    uint64_t x[3] = { 0x8000000000000001ULL, 0x0123456789ABCDEFULL, 0xF000000000000000ULL };
    uint64_t a[3], b[3], tmp[3];
    size_t k;

    memcpy(a, x, sizeof x);
    words_shr1(a, 0, 3);
    assert(a[0] == 0xC000000000000000ULL);
    assert(a[1] == 0x0091A2B3C4D5E6F7ULL);
    assert(a[2] == 0x7800000000000000ULL);
    memcpy(a, x, sizeof x);
    words_shr1(a, 1, 3);
    assert(a[2] == 0xF800000000000000ULL);

    words_shr_public(a, x, 0, 3);
    assert(memcmp(a, x, sizeof x) == 0);
    words_shr_public(a, x, 64, 3);
    assert(a[0] == x[1] && a[1] == x[2] && a[2] == 0);
    words_shr_public(a, x, 68, 3);
    assert(a[0] == 0x00123456789ABCDEULL);
    assert(a[1] == 0x0F00000000000000ULL && a[2] == 0);
    words_shr_public(a, x, 192, 3);
    assert(a[0] == 0 && a[1] == 0 && a[2] == 0);

    words_shl_public(a, x, 0, 3);
    assert(memcmp(a, x, sizeof x) == 0);
    words_shl_public(a, x, 64, 3);
    assert(a[0] == 0 && a[1] == x[0] && a[2] == x[1]);
    words_shl_public(a, x, 4, 3);
    assert(a[0] == 0x0000000000000010ULL);
    assert(a[1] == 0x123456789ABCDEF8ULL);
    assert(a[2] == 0x0000000000000000ULL);
    words_shl_public(a, x, 192, 3);
    assert(a[0] == 0 && a[1] == 0 && a[2] == 0);

    /* The secret shifts give the same result as the public ones */
    for (k=0; k<=192; k++) {
        memcpy(a, x, sizeof x);
        words_shr_secret(a, k, tmp, 3);
        words_shr_public(b, x, k, 3);
        assert(memcmp(a, b, sizeof a) == 0);

        memcpy(a, x, sizeof x);
        words_shl_secret(a, k, tmp, 3);
        words_shl_public(b, x, k, 3);
        assert(memcmp(a, b, sizeof a) == 0);
    }

    /* Trailing zeros */
    a[0] = 0; a[1] = 0; a[2] = 0;
    assert(words_ctz(a, 3) == 192);
    a[2] = 1;
    assert(words_ctz(a, 3) == 128);
    a[1] = 0x100;
    assert(words_ctz(a, 3) == 72);
    a[0] = 0x8000000000000000ULL;
    assert(words_ctz(a, 3) == 63);
    a[0] = 1;
    assert(words_ctz(a, 3) == 0);
}

void test_muladd_and_or(void)
{
    const uint64_t wc[2] = { MAX64, MAX64 };
    const uint64_t wa[2] = { 0xF0F0, 0xFF00 };
    const uint64_t wb[1] = { 0x0FF0 };
    Nat *a, *b, *c, *one, *out;

    a = make(2, wa, 2);
    b = make(1, wb, 1);
    c = make(2, wc, 2);
    one = make1(1, 1);
    nat_new(&out, 3);

    /* 2^128 - 1 + 1*1: the carry goes through all the words */
    assert(nat_muladd(out, c, one, one) == 0);
    assert(out->w[0] == 0 && out->w[1] == 0 && out->w[2] == 1);
    assert(nat_muladd(out, c, out, one) == ERR_VALUE);

    /* c + a*b, compared with the separate operations */
    {
        Nat *prod, *sum;
        nat_new(&prod, 3);
        nat_new(&sum, 3);
        nat_mul(prod, a, b);
        nat_add(sum, prod, c);
        assert(nat_muladd(out, c, a, b) == 0);
        assert(nat_cmp(out, sum) == 0);
        nat_free(prod);
        nat_free(sum);
    }

    assert(nat_and(out, a, b) == 0);
    assert(out->w[0] == 0x00F0 && out->w[1] == 0 && out->w[2] == 0);
    assert(nat_or(out, a, b) == 0);
    assert(out->w[0] == 0xFFF0 && out->w[1] == 0xFF00 && out->w[2] == 0);

    nat_free(a);
    nat_free(b);
    nat_free(c);
    nat_free(one);
    nat_free(out);
}

void test_divmod_words(void)
{
    const uint64_t wa[3] = { 7, 0, 5 };
    uint64_t q[3], r[1];
    Nat *a, *b;

    a = make(3, wa, 3);
    b = make1(1, 1000003);

    /* Quotient only, truncated to two words */
    assert(nat_divmod_words(q, 2, NULL, a, b) == 0);
    /* (5*2^128 + 7) // 1000003, computed with Python */
    assert(q[0] == 0xC0E0C57BE43FA822ULL);
    assert(q[1] == 0x000053E2C5A570F8ULL);

    /* Remainder only */
    assert(nat_divmod_words(NULL, 0, r, a, b) == 0);
    assert(r[0] == 15137);

    nat_free(a);
    nat_free(b);
}

void test_mod_helpers(void)
{
    /* n = 2^128 - 159 (prime), close to 2^128 to exercise the carry */
    uint64_t n[2] = { MAX64 - 158, MAX64 };
    uint64_t a[2] = { MAX64 - 200, MAX64 };   /* n - 42 */
    uint64_t b[2] = { 100, 0 };
    uint64_t out[2], x[2];

    mod_add(out, a, b, n, 2);                  /* n - 42 + 100 = 58 */
    assert(out[0] == 58 && out[1] == 0);
    mod_add(out, a, a, n, 2);                  /* 2n - 84 = n - 84 */
    assert(out[0] == MAX64 - 242 && out[1] == MAX64);
    mod_add(out, b, b, n, 2);
    assert(out[0] == 200 && out[1] == 0);

    mod_sub(out, b, a, n, 2);                  /* 100 - (n - 42) = 142 */
    assert(out[0] == 142 && out[1] == 0);
    mod_sub(out, a, b, n, 2);
    assert(out[0] == MAX64 - 300 && out[1] == MAX64);
    mod_sub(out, b, b, n, 2);
    assert(out[0] == 0 && out[1] == 0);

    /* x/2 mod n */
    x[0] = 100; x[1] = 0;
    mod_half(x, n, 2);
    assert(x[0] == 50 && x[1] == 0);
    x[0] = 1; x[1] = 0;
    mod_half(x, n, 2);                         /* (n + 1)/2 */
    assert(x[0] == 0xFFFFFFFFFFFFFFB1ULL);
    assert(x[1] == 0x7FFFFFFFFFFFFFFFULL);
}

void test_montgomery(void)
{
    MontCtx *ctx;
    Nat *n, *e;
    uint64_t x[2], y[2], z[2];
    const uint64_t w127[2] = { MAX64, 0x7FFFFFFFFFFFFFFFULL };

    /* n = 2^127 - 1: R mod n = 2, R^2 mod n = 4, m0 = 1 */
    n = make(2, w127, 2);
    assert(mont_ctx_new(&ctx, n) == 0);
    assert(ctx->nw == 2 && ctx->m0 == 1);
    assert(ctx->one[0] == 2 && ctx->one[1] == 0);
    assert(ctx->r2[0] == 4 && ctx->r2[1] == 0);
    assert(ctx->unit[0] == 1 && ctx->unit[1] == 0);

    /* x*R mod n = 2x */
    x[0] = 5; x[1] = 0;
    mont_to(y, x, ctx);
    assert(y[0] == 10 && y[1] == 0);
    mont_from(z, y, ctx);
    assert(z[0] == 5 && z[1] == 0);

    /* 3*7 in Montgomery form, and in place */
    x[0] = 3; y[0] = 7; x[1] = y[1] = 0;
    mont_to(x, x, ctx);
    mont_to(y, y, ctx);
    mont_mul(x, x, y, ctx);
    assert(x[0] == 42 && x[1] == 0);

    /* 7^(2^100 + 3) mod n */
    {
        const uint64_t we[2] = { 3, (uint64_t)1 << 36 };
        e = make(2, we, 2);
        x[0] = 7; x[1] = 0;
        mont_to(x, x, ctx);
        assert(mont_pow(y, x, e, 64*e->nw, ctx) == 0);
        mont_from(y, y, ctx);
        assert(y[0] == 0xCE19D7661370F5B0ULL && y[1] == 0x4EFF7E6DC4621C8AULL);
        nat_free(e);
    }
    mont_ctx_free(ctx);
    nat_free(n);

    /* One-word modulus */
    n = make1(1, 1000003);
    assert(mont_ctx_new(&ctx, n) == 0);
    assert(ctx->m0 == 0x206E7802877E6595ULL);
    assert(ctx->one[0] == 350687);
    assert(ctx->r2[0] == 3026);
    e = make1(1, 1000);
    x[0] = 3;
    mont_to(x, x, ctx);
    assert(mont_pow(y, x, e, 64*e->nw, ctx) == 0);
    mont_from(y, y, ctx);
    assert(y[0] == 73216);
    nat_free(e);
    mont_ctx_free(ctx);
    nat_free(n);

    /* Even modulus */
    n = make1(1, 1000002);
    assert(mont_ctx_new(&ctx, n) == ERR_VALUE);
    nat_free(n);
    mont_ctx_free(NULL);
}

void test_mont_pow_vs_mulmod(void)
{
    /* Montgomery exponentiation against square-and-multiply with mulmod_words */
    const uint64_t wn[3] = { 0x1234567890ABCDEFULL | 1, 0xFEDCBA0987654321ULL, 0x0F0F0F0F0F0F0F0FULL };
    const uint64_t wb[3] = { 0x1111111111111111ULL, 0x2222222222222222ULL, 0x0303030303030303ULL };
    const uint64_t we[2] = { 0xDEADBEEFCAFEBABEULL, 0x5 };
    MontCtx *ctx;
    Nat *n, *e, *prod;
    uint64_t base[3], acc[3], ref[3];
    size_t i;

    n = make(3, wn, 3);
    e = make(2, we, 2);
    nat_new(&prod, 6);
    memcpy(base, wb, sizeof base);

    ref[0] = 1; ref[1] = ref[2] = 0;
    for (i=128; i-- > 0;) {
        assert(mulmod_words(ref, ref, ref, n, prod) == 0);
        if ((e->w[i / 64] >> (i % 64)) & 1)
            assert(mulmod_words(ref, ref, base, n, prod) == 0);
    }

    assert(mont_ctx_new(&ctx, n) == 0);
    mont_to(acc, base, ctx);
    assert(mont_pow(acc, acc, e, 128, ctx) == 0);
    mont_from(acc, acc, ctx);
    assert(memcmp(acc, ref, sizeof acc) == 0);

    mont_ctx_free(ctx);
    nat_free(n);
    nat_free(e);
    nat_free(prod);
}

void test_inv_odd(void)
{
    uint64_t n[2] = { MAX64, 0x7FFFFFFFFFFFFFFFULL };   /* 2^127 - 1 */
    uint64_t a[2] = { 12345, 0 };
    uint64_t out[2];

    assert(inv_odd(out, a, n, 2) == 0);
    assert(out[0] == 0x802D1FBFA1C53B1FULL && out[1] == 0x103219D6A66FB0B3ULL);

    a[0] = 0;
    assert(inv_odd(out, a, n, 2) == ERR_VALUE);

    /* gcd(6, 15) = 3 */
    {
        uint64_t n15[1] = { 15 }, a6[1] = { 6 }, a7[1] = { 7 }, o[1];
        assert(inv_odd(o, a6, n15, 1) == ERR_VALUE);
        assert(inv_odd(o, a7, n15, 1) == 0);
        assert(o[0] == 13);
    }

    /* Modulo 1, everything is 0 */
    {
        uint64_t n1[1] = { 1 }, a0[1] = { 0 }, o[1] = { 99 };
        assert(inv_odd(o, a0, n1, 1) == 0);
        assert(o[0] == 0);
    }
}

void test_mulmod_words(void)
{
    uint64_t x[1] = { 999999 }, y[1] = { 123456 }, out[1];
    Nat *m, *prod;

    m = make1(1, 1000003);
    nat_new(&prod, 2);
    assert(mulmod_words(out, x, y, m, prod) == 0);
    assert(out[0] == (uint64_t)999999 * 123456 % 1000003);
    nat_free(m);
    nat_free(prod);
}

void test_argument_checks(void)
{
    Nat *a, *b, *z, *even, *out, *q;

    a = make1(1, 100);
    b = make1(1, 7);
    z = make1(1, 0);
    even = make1(1, 1000);
    nat_new(&out, 2);
    nat_new(&q, 2);

    /* The output must not be the same object as an input */
    assert(nat_shl(a, a, 1) == ERR_VALUE);
    assert(nat_shr(a, a, 1) == ERR_VALUE);
    assert(nat_divmod(q, q, a, b) == ERR_VALUE);
    assert(nat_divmod(a, q, a, b) == ERR_VALUE);
    assert(nat_divmod(q, b, a, b) == ERR_VALUE);

    /* Zero modulus */
    assert(nat_mulmod(out, a, b, z) == ERR_VALUE);
    assert(nat_powmod(out, a, b, 64, z) == ERR_VALUE);
    assert(nat_invmod(out, a, z) == ERR_VALUE);

    /* Even modulus where an odd one is required */
    assert(nat_miller_rabin(out, even, b) == ERR_VALUE);
    assert(nat_lucas(out, even, 5, 0) == ERR_VALUE);
    assert(nat_jacobi(out, a, even, 0) == ERR_VALUE);

    nat_free(a);
    nat_free(b);
    nat_free(z);
    nat_free(even);
    nat_free(out);
    nat_free(q);
}

void test_lucas_negative_d(void)
{
    /* For 2^89 - 1, D = -7 is the first in 5, -7, 9, ... with (D/p) = -1 */
    const uint64_t wp[2] = { MAX64, ((uint64_t)1 << 25) - 1 };
    Nat *p, *c, *out;

    p = make(2, wp, 2);
    c = make1(1, (uint64_t)1000003 * 1000033);
    nat_new(&out, 1);

    assert(nat_lucas(out, p, 7, 1) == 0);
    assert(out->w[0] == 1);
    assert(nat_lucas(out, c, 7, 1) == 0);
    assert(out->w[0] == 0);

    nat_free(p);
    nat_free(c);
    nat_free(out);
}

#if defined(HAVE_UINT128)
static uint64_t div128_ref(uint64_t hi, uint64_t lo, uint64_t d)
{
    __uint128_t u = ((__uint128_t)hi << 64) | lo;
    __uint128_t q = u / d;
    return (q >> 64) ? UINT64_MAX : (uint64_t)q;
}
#endif

void test_div128(void)
{
    /* Fixed values: (2^127) / 2^63 = 2^64 does not fit */
    assert(div128_ct((uint64_t)1 << 63, 0, (uint64_t)1 << 63) == MAX64);
    assert(div128_ct(0, 12345, (uint64_t)1 << 63) == 0);
    assert(div128_ct(1, 0, (uint64_t)1 << 63) == 2);
    assert(div128_ct(MAX64 - 1, MAX64, MAX64) == MAX64);
    assert(reciprocal_ct((uint64_t)1 << 63) == MAX64);
    assert(reciprocal_ct(MAX64) == 1);
    assert(div128_preinv_ct(1, 0, (uint64_t)1 << 63, reciprocal_ct((uint64_t)1 << 63)) == 2);

#if defined(HAVE_UINT128)
    {
        int i;

        for (i=0; i<200000; i++) {
            uint64_t d = rnd() | ((uint64_t)1 << 63);
            uint64_t lo = rnd();
            uint64_t hi;

            switch (i % 4) {
            case 0: hi = d; break;
            case 1: hi = d - 1; break;
            case 2: hi = 0; break;
            default: hi = rnd() % d;
            }
            assert(div128_ct(hi, lo, d) == div128_ref(hi, lo, d));
            assert(div128_preinv_ct(hi, lo, d, reciprocal_ct(d)) == div128_ref(hi, lo, d));
        }
    }
#endif
}

void test_divmod_random(void)
{
    /* q*b + r == a and r < b, for random sizes (also with leading zero words) */
    int it;

    for (it=0; it<2000; it++) {
        size_t na = 1 + rnd() % 9, nb = 1 + rnd() % 9, i;
        Nat *a, *b, *q, *r, *check;

        nat_new(&a, na);
        nat_new(&b, nb);
        for (i=0; i<na; i++)
            a->w[i] = rnd();
        for (i=0; i<nb; i++)
            b->w[i] = (it % 5 == 0 && i > 0) ? 0 : rnd();
        if (it % 7 == 0)
            b->w[nb - 1] = MAX64;
        b->w[0] |= 1;

        nat_new(&q, na);
        nat_new(&r, nb);
        nat_new(&check, na + nb + 1);
        assert(nat_divmod(q, r, a, b) == 0);
        assert(nat_cmp(r, b) == -1);
        assert(nat_muladd(check, r, q, b) == 0);
        assert(nat_cmp(check, a) == 0);

        nat_free(a);
        nat_free(b);
        nat_free(q);
        nat_free(r);
        nat_free(check);
    }
}

void test_mont_sqr(void)
{
    int it;

    for (it=0; it<2000; it++) {
        size_t nw = 1 + rnd() % 12, i;
        uint64_t a[12], o1[12], o2[12], rem[12];
        Nat *n, an, rn;
        MontCtx *ctx;

        nat_new(&n, nw);
        for (i=0; i<nw; i++)
            n->w[i] = rnd();
        if (it % 3 == 0)
            n->w[nw - 1] = MAX64;
        n->w[0] |= 1;
        assert(mont_ctx_new(&ctx, n) == 0);

        /* a < n */
        for (i=0; i<nw; i++)
            a[i] = rnd();
        if (it % 4 == 0) {
            memcpy(a, n->w, nw*sizeof(uint64_t));
            a[0] -= 1;
        }
        an.nw = rn.nw = nw;
        an.w = a;
        rn.w = rem;
        assert(nat_divmod(NULL, &rn, &an, n) == 0);

        mont_mul(o1, rem, rem, ctx);
        mont_sqr(o2, rem, ctx);
        assert(memcmp(o1, o2, nw*sizeof(uint64_t)) == 0);
        mont_sqr(rem, rem, ctx);                      /* in place */
        assert(memcmp(o1, rem, nw*sizeof(uint64_t)) == 0);

        mont_ctx_free(ctx);
        nat_free(n);
    }
}

void test_inv_odd_vs_simple(void)
{
    int it, no_inverse = 0;

    for (it=0; it<3000; it++) {
        size_t nw = 1 + rnd() % 8, i, top;
        uint64_t a[8], n[8], o1[8], o2[8];
        int r1, r2;

        for (i=0; i<nw; i++) {
            n[i] = rnd();
            a[i] = rnd();
        }
        if (it % 5 == 0)
            for (i=nw/2; i<nw; i++)
                n[i] = 0;
        if (it % 5 == 1) {
            memset(n, 0, sizeof n);
            n[0] = 3*5*7*11*13;
        }
        n[0] |= 1;

        /* a < n */
        for (top=nw; top>1 && n[top - 1] == 0; top--);
        for (i=top; i<nw; i++)
            a[i] = 0;
        a[top - 1] %= n[top - 1];

        r1 = inv_odd(o1, a, n, nw);
        r2 = inv_odd_simple(o2, a, n, nw);
        assert(r1 == r2);
        if (r1 == 0)
            assert(memcmp(o1, o2, nw*sizeof(uint64_t)) == 0);
        else
            no_inverse++;
    }
    assert(no_inverse > 0);
}

void test_bgcd_helpers(void)
{
    uint64_t x[2] = { 10, 0 }, y[2] = { 3, 0 }, out[3], a, b;

    /* 10*5 + 3*(-7) = 29 */
    lin_comb(out, x, y, 5, -7, 2);
    assert(out[0] == 29 && out[1] == 0 && out[2] == 0);
    /* 10*(-5) + 3*7 = -29 */
    lin_comb(out, x, y, -5, 7, 2);
    assert(out[0] == (uint64_t)-29 && out[1] == MAX64 && out[2] == MAX64);
    /* With full words and the largest factors */
    {
        uint64_t xm[1] = { MAX64 }, ym[1] = { MAX64 }, o[2];
        lin_comb(o, xm, ym, (int64_t)1 << 31, -((int64_t)1 << 31), 1);
        assert(o[0] == 0 && o[1] == 0);
        lin_comb(o, xm, ym, (int64_t)1 << 31, 0, 1);
        /* (2^64 - 1) * 2^31 */
        assert(o[0] == (uint64_t)0 - ((uint64_t)1 << 31) && o[1] == ((uint64_t)1 << 31) - 1);
    }

    /* Arithmetic shift by 31 */
    out[0] = (uint64_t)1 << 40; out[1] = 0; out[2] = 0;
    shr_signed(out, 2);
    assert(out[0] == 512 && out[1] == 0 && out[2] == 0);
    out[0] = (uint64_t)-((int64_t)1 << 40); out[1] = MAX64; out[2] = MAX64;
    shr_signed(out, 2);
    assert(out[0] == (uint64_t)-512 && out[1] == MAX64 && out[2] == MAX64);

    /* Conditional negation */
    out[0] = 5; out[1] = 0; out[2] = 0;
    cond_negate(0, out, 2);
    assert(out[0] == 5 && out[1] == 0 && out[2] == 0);
    cond_negate(MAX64, out, 2);
    assert(out[0] == (uint64_t)-5 && out[1] == MAX64 && out[2] == MAX64);
    cond_negate(MAX64, out, 2);
    assert(out[0] == 5 && out[1] == 0 && out[2] == 0);

    /* Approximations: small values are taken as they are */
    {
        uint64_t sa[3] = { 0x123456789ULL, 0, 0 }, sb[3] = { 77, 0, 0 };
        approximations(&a, &b, sa, sb, 3);
        assert(a == 0x123456789ULL && b == 77);
    }
    /* Large values: low 31 bits, and the top 33 bits aligned on the larger one */
    {
        uint64_t la[3] = { 0xFFFFFFFFFFFFFFFFULL, 0x0123456789ABCDEFULL, 0x00000000000000F0ULL };
        uint64_t lb[3] = { 0x0000000000000005ULL, 0x0000000000000000ULL, 0x0000000000000001ULL };
        /* len(a) = 136 bits: the top 33 bits of a are bits 103..135 */
        approximations(&a, &b, la, lb, 3);
        assert((a & 0x7FFFFFFF) == 0x7FFFFFFF);
        assert(a >> 31 == ((0xF0ULL << 25) | (0x0123456789ABCDEFULL >> 39)));
        assert((b & 0x7FFFFFFF) == 5);
        assert(b >> 31 == ((uint64_t)1 << 25));
    }

    /* (u*f + v*g) / 2^31 mod n */
    {
        uint64_t n[1] = { 1000003 }, u[1] = { 123 }, v[1] = { 456 }, r[1], t[3], kn[2];
        uint64_t n0inv = n[0], i;
        uint64_t inv2_31 = 1;

        for (i=0; i<5; i++)
            n0inv *= 2 - n[0]*n0inv;
        n0inv = 0 - n0inv;
        /* 2^-31 mod n, computed by halving */
        for (i=0; i<31; i++)
            inv2_31 = (inv2_31 & 1) ? (inv2_31 + n[0]) / 2 : inv2_31 / 2;

        mod_lin_comb(r, u, v, 1000, -77, n, n0inv, t, kn, 1);
        /* 123*1000 - 456*77 = 87888 */
        assert(r[0] == (87888 * inv2_31) % n[0]);
        mod_lin_comb(r, u, v, -1000, 77, n, n0inv, t, kn, 1);
        assert(r[0] == ((n[0] - 87888) * inv2_31) % n[0]);
    }
}

void test_addmul_row(void)
{
    /* Against a plain computation, for all lengths up to 40 words
     * (every remainder of the 4-word unrolling in the BMI2/ADX build) */
    size_t nw, j;
    int it;

    for (nw=1; nw<=40; nw++) {
        for (it=0; it<50; it++) {
            uint64_t t[40], ref[41], a[40], b, h, c;

            for (j=0; j<nw; j++) {
                t[j] = (it % 5 == 0) ? MAX64 : rnd();
                a[j] = (it % 7 == 0) ? MAX64 : rnd();
            }
            b = (it % 3 == 0) ? MAX64 : rnd();

            memcpy(ref, t, nw*sizeof(uint64_t));
            c = 0;
            for (j=0; j<nw; j++)
                ref[j] = ct_mac(a[j], b, ref[j], c, &c);
            ref[nw] = c;

            h = addmul_row(t, a, b, nw);
            assert(memcmp(t, ref, nw*sizeof(uint64_t)) == 0);
            assert(h == ref[nw]);
        }
    }
}

int main(void)
{
#if defined(TEST_BMI2_ADX)
    if (!have_bmi2_adx()) {
        printf("Skipped: the CPU does not support BMI2 and ADX\n");
        return 0;
    }
#endif
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
    test_ct_misc();
    test_memory_helpers();
    test_copy_and_conversions();
    test_words_compare_select();
    test_words_add_sub();
    test_words_shifts();
    test_muladd_and_or();
    test_divmod_words();
    test_mod_helpers();
    test_montgomery();
    test_mont_pow_vs_mulmod();
    test_inv_odd();
    test_mulmod_words();
    test_argument_checks();
    test_lucas_negative_d();
    test_div128();
    test_divmod_random();
    test_mont_sqr();
    test_inv_odd_vs_simple();
    test_bgcd_helpers();
    test_addmul_row();
    return 0;
}
