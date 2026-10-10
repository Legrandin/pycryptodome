/*
 * Unit tests of ec_common.c (what the elliptic curves on the nat
 * library have in common). The scalar functions (blinding, Booth
 * recoding) are tested in test_ec_nat.c.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "nat.h"
#include "ec_common.h"

#define NW 4

static uint64_t rnd_state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return rnd_state;
}

/* The prime of P-256 */
static const uint64_t p256[NW] = {
    0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
};

static Nat *modulus(void)
{
    Nat *n;

    assert(nat_new(&n, NW) == 0);
    memcpy(n->w, p256, sizeof p256);
    return n;
}

/** A random number smaller than p (the top word of p is not the maximum) **/
static void random_fe(uint64_t *x)
{
    unsigned i;

    for (i=0; i<NW; i++)
        x[i] = rnd();
    x[NW-1] %= p256[NW-1];
}

static void to_bytes(uint8_t *out, const uint64_t *x)
{
    unsigned i, j;

    for (i=0; i<NW; i++)
        for (j=0; j<8; j++)
            out[8*NW - 1 - 8*i - j] = (uint8_t)(x[i] >> (8*j));
}

static void test_ws(const MontCtx *field)
{
    EcWs ws;
    unsigned i, j;

    assert(ec_ws_new(&ws, field) == 0);
    assert(ws.nw == NW);
    assert(ws.m != field && ws.m->n == field->n);
    assert(words_is_zero(ws.zero, NW));
    for (i=0; i<EC_WS_TEMPS; i++) {
        /* Distinct and not overlapping */
        assert(ws.t[i] != ws.zero);
        for (j=0; j<i; j++)
            assert(ws.t[i] >= ws.t[j] + NW || ws.t[j] >= ws.t[i] + NW);
        memset(ws.t[i], 0xAA, NW*8);
    }
    assert(words_is_zero(ws.zero, NW));
    ec_ws_free(&ws);
}

/* The field operations, against nat_mulmod() and nat_submod() */
static void test_field(const MontCtx *field, const Nat *n, const Nat *p_minus_2)
{
    EcWs ws;
    uint64_t a[NW], b[NW], am[NW], bm[NW], r[NW];
    uint8_t buf[8*NW + 8];
    Nat *na, *nb, *nr, *expected;
    unsigned t;

    assert(ec_ws_new(&ws, field) == 0);
    assert(nat_new(&na, NW) == 0);
    assert(nat_new(&nb, NW) == 0);
    assert(nat_new(&nr, NW) == 0);
    assert(nat_new(&expected, NW) == 0);

    for (t=0; t<200; t++) {
        random_fe(a);
        random_fe(b);
        if (t == 0)
            memset(a, 0, sizeof a);
        if (t == 1)
            memcpy(b, p256, sizeof b), b[0]--;          /* p - 1 */
        memcpy(na->w, a, sizeof a);
        memcpy(nb->w, b, sizeof b);

        /* fe_from_bytes and fe_to_bytes */
        to_bytes(buf, a);
        assert(fe_from_bytes(am, &ws, buf, 8*NW, 0) == 0);
        to_bytes(buf, b);
        assert(fe_from_bytes(bm, &ws, buf, 8*NW, 0) == 0);
        assert(fe_to_bytes(buf, 8*NW, &ws, am) == 0);
        {
            uint8_t ab[8*NW];

            to_bytes(ab, a);
            assert(memcmp(buf, ab, sizeof ab) == 0);
        }

        /* mul, sqr */
        fe_mul(&ws, r, am, bm);
        mont_from(r, r, ws.m);
        assert(nat_mulmod(expected, na, nb, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);
        fe_sqr(&ws, r, am);
        mont_from(r, r, ws.m);
        assert(nat_mulmod(expected, na, na, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);

        /* add, sub, neg (also in place) */
        fe_copy(&ws, r, am);
        fe_add(&ws, r, r, bm);
        fe_sub(&ws, r, r, bm);
        assert(memcmp(r, am, sizeof r) == 0);
        fe_sub(&ws, r, am, bm);
        mont_from(r, r, ws.m);
        assert(nat_submod(expected, na, nb, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);
        fe_neg(&ws, r, am);
        fe_add(&ws, r, r, am);
        assert(words_is_zero(r, NW));

        /* inv: a * 1/a = 1 (R in Montgomery form), and 1/0 = 0 */
        assert(fe_inv(&ws, r, am, p_minus_2) == 0);
        if (t == 0) {
            assert(words_is_zero(r, NW));
        } else {
            fe_mul(&ws, r, r, am);
            assert(memcmp(r, field->one, sizeof r) == 0);
        }
    }

    nat_free(na);
    nat_free(nb);
    nat_free(nr);
    nat_free(expected);
    ec_ws_free(&ws);
}

/* fe_from_bytes: the range checks and the reduction; fe_to_bytes: the lengths */
static void test_conversions(const MontCtx *field)
{
    EcWs ws;
    uint8_t buf[8*NW + 8], out[8*NW + 8];
    uint64_t x[NW], p5[NW];
    unsigned i;

    assert(ec_ws_new(&ws, field) == 0);

    /* p is not accepted, unless reduced (to 0) */
    to_bytes(buf, p256);
    assert(fe_from_bytes(x, &ws, buf, 8*NW, 0) == ERR_VALUE);
    assert(fe_from_bytes(x, &ws, buf, 8*NW, 1) == 0);
    assert(words_is_zero(x, NW));

    /* p + 5 reduced is 5 */
    p5[0] = 4;                  /* the low word of p is 2^64 - 1 */
    p5[1] = p256[1] + 1;
    p5[2] = p256[2];
    p5[3] = p256[3];
    to_bytes(buf, p5);
    assert(fe_from_bytes(x, &ws, buf, 8*NW, 0) == ERR_VALUE);
    assert(fe_from_bytes(x, &ws, buf, 8*NW, 1) == 0);
    assert(fe_to_bytes(out, 8*NW, &ws, x) == 0);
    for (i=0; i<8*NW - 1; i++)
        assert(out[i] == 0);
    assert(out[8*NW - 1] == 5);

    /* Shorter input; longer input with leading zeros; longer output */
    assert(fe_from_bytes(x, &ws, (const uint8_t*)"\x07", 1, 0) == 0);
    memset(buf, 0, 8);
    memset(buf + 8, 0, 8*NW);
    buf[8*NW + 7] = 7;
    assert(fe_from_bytes(p5, &ws, buf, 8*NW + 8, 0) == 0);
    assert(memcmp(x, p5, sizeof x) == 0);
    assert(fe_to_bytes(out, 8*NW + 8, &ws, x) == 0);
    for (i=0; i<8*NW + 7; i++)
        assert(out[i] == 0);
    assert(out[8*NW + 7] == 7);

    /* Too long */
    buf[0] = 1;
    assert(fe_from_bytes(x, &ws, buf, 8*NW + 8, 1) != 0);
    /* A number that needs all the bytes (p - 1) */
    memcpy(p5, p256, sizeof p5);
    p5[0]--;
    to_bytes(buf, p5);
    assert(fe_from_bytes(x, &ws, buf, 8*NW, 0) == 0);
    assert(fe_to_bytes(out, 8*NW - 1, &ws, x) != 0);
    assert(fe_to_bytes(out, 8*NW - 1, &ws, field->one) == 0);

    ec_ws_free(&ws);
}

static void test_random(const MontCtx *field)
{
    EcWs ws;
    uint64_t a[NW], b[NW], state1 = 1, state2 = 1;
    unsigned t, bits;

    assert(ec_ws_new(&ws, field) == 0);
    for (t=0; t<1000; t++) {
        fe_random(&ws, a, 256, &state1);
        fe_random(&ws, b, 256, &state2);
        assert(memcmp(a, b, sizeof a) == 0);    /* deterministic */
        assert((a[0] & 1) == 1);                /* not zero */
        assert(a[NW-1] >> 63 == 0);             /* fewer bits than p */
    }
    /* Shorter field elements */
    for (bits=2; bits<=256; bits+=37) {
        fe_random(&ws, a, bits, &state1);
        assert(a[0] & 1);
        for (t=bits-1; t<64*NW; t++)
            assert(((a[t/64] >> (t%64)) & 1) == 0);
    }
    /* Different states give different values */
    state2 = 2;
    fe_random(&ws, a, 256, &state1);
    fe_random(&ws, b, 256, &state2);
    assert(memcmp(a, b, sizeof a) != 0);
    ec_ws_free(&ws);
}

static void test_sizes(void)
{
    size_t bits;

    assert(ec_k_words(256) == 5);
    assert(ec_windows(256) == 65);
    assert(ec_k_words(448) == 8);
    assert(ec_windows(448) == 103);
    for (bits=1; bits<1000; bits++) {
        size_t kbits = bits + EC_BLINDING_BITS;

        assert(64*ec_k_words(bits) >= kbits && 64*(ec_k_words(bits) - 1) < kbits);
        /* At least one bit above the scalar, for the top Booth digit */
        assert(EC_WINDOW*ec_windows(bits) >= kbits + 1);
        assert(EC_WINDOW*(ec_windows(bits) - 1) < kbits + 1);
    }
}

static void test_table_select(void)
{
    uint64_t table[17*3], out[3];
    size_t i;

    for (i=0; i<17*3; i++)
        table[i] = rnd();
    for (i=0; i<17; i++) {
        ec_table_select(out, table, 17, 3, i);
        assert(memcmp(out, table + 3*i, sizeof out) == 0);
    }
    /* Beyond the table: zero */
    ec_table_select(out, table, 17, 3, 17);
    assert(out[0] == 0 && out[1] == 0 && out[2] == 0);
    ec_table_select(out, table, 17, 3, (uint64_t)0 - 1);
    assert(out[0] == 0 && out[1] == 0 && out[2] == 0);
}

/* Batch conversion to affine, against one inversion per point */
static void test_batch_to_affine(const MontCtx *field, const Nat *p_minus_2)
{
    EcWs ws;
    uint64_t proj[10*3*NW], affine[10*2*NW], zinv[NW], x[NW];
    size_t count, k;

    assert(ec_ws_new(&ws, field) == 0);
    for (count=1; count<=10; count++) {
        for (k=0; k<count; k++) {
            random_fe(proj + 3*k*NW);
            random_fe(proj + 3*k*NW + NW);
            random_fe(proj + 3*k*NW + 2*NW);
            proj[3*k*NW + 2*NW] |= 1;           /* Z != 0 */
        }
        assert(ec_batch_to_affine(&ws, affine, proj, count, p_minus_2) == 0);
        for (k=0; k<count; k++) {
            assert(fe_inv(&ws, zinv, proj + 3*k*NW + 2*NW, p_minus_2) == 0);
            fe_mul(&ws, x, proj + 3*k*NW, zinv);
            assert(memcmp(x, affine + 2*k*NW, sizeof x) == 0);
            fe_mul(&ws, x, proj + 3*k*NW + NW, zinv);
            assert(memcmp(x, affine + 2*k*NW + NW, sizeof x) == 0);
        }
    }
    ec_ws_free(&ws);
}

int main(void)
{
    MontCtx *field;
    Nat *n, *two, *p_minus_2;

    n = modulus();
    assert(nat_new(&two, 1) == 0);
    assert(nat_new(&p_minus_2, NW) == 0);
    two->w[0] = 2;
    assert(nat_sub(p_minus_2, n, two) == 0);
    assert(mont_ctx_new(&field, n) == 0);

    test_ws(field);
    test_field(field, n, p_minus_2);
    test_conversions(field);
    test_random(field);
    test_sizes();
    test_table_select();
    test_batch_to_affine(field, p_minus_2);

    mont_ctx_free(field);
    nat_free(n);
    nat_free(two);
    nat_free(p_minus_2);
    return 0;
}
