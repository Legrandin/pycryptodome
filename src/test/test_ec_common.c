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
#include "siphash.h"

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

static void test_ws(const EcField *field)
{
    EcWs ws;
    unsigned i, j;

    assert(ec_ws_new(&ws, field) == 0);
    assert(ws.nw == NW);
    assert(ws.f == field && ws.m != field->m && ws.m->n == field->m->n);
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
static void test_field(const EcField *field, const Nat *n)
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
        if (t == 1) {
            memcpy(b, p256, sizeof b);
            b[0]--;                                     /* p - 1 */
        }
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
        fe_to_words(&ws, r, r);
        assert(nat_mulmod(expected, na, nb, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);
        fe_sqr(&ws, r, am);
        fe_to_words(&ws, r, r);
        assert(nat_mulmod(expected, na, na, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);

        /* add, sub, neg (also in place) */
        fe_copy(&ws, r, am);
        fe_add(&ws, r, r, bm);
        fe_sub(&ws, r, r, bm);
        assert(memcmp(r, am, sizeof r) == 0);
        fe_sub(&ws, r, am, bm);
        fe_to_words(&ws, r, r);
        assert(nat_submod(expected, na, nb, n) == 0);
        assert(memcmp(r, expected->w, sizeof r) == 0);
        fe_neg(&ws, r, am);
        fe_add(&ws, r, r, am);
        assert(words_is_zero(r, NW));

        /* inv: a * 1/a = 1 (R in Montgomery form), and 1/0 = 0 */
        assert(fe_inv(&ws, r, am) == 0);
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
static void test_conversions(const EcField *field)
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

static void test_random(const EcField *field)
{
    EcWs ws;
    uint64_t a[NW], b[NW];
    BlindPrf prf1, prf2;
    unsigned t, bits;

    blind_prf_init(&prf1, 1);
    blind_prf_init(&prf2, 1);
    assert(ec_ws_new(&ws, field) == 0);
    for (t=0; t<1000; t++) {
        fe_random(&ws, a, 256, &prf1);
        fe_random(&ws, b, 256, &prf2);
        assert(memcmp(a, b, sizeof a) == 0);    /* deterministic */
        assert((a[0] & 1) == 1);                /* not zero */
        assert(a[NW-1] >> 63 == 0);             /* fewer bits than p */
    }
    /* Shorter field elements */
    for (bits=2; bits<=256; bits+=37) {
        fe_random(&ws, a, bits, &prf1);
        assert(a[0] & 1);
        for (t=bits-1; t<64*NW; t++)
            assert(((a[t/64] >> (t%64)) & 1) == 0);
    }
    /* Different seeds give different values */
    blind_prf_init(&prf2, 2);
    fe_random(&ws, a, 256, &prf1);
    fe_random(&ws, b, 256, &prf2);
    assert(memcmp(a, b, sizeof a) != 0);
    ec_ws_free(&ws);
}

/* The generator that expands the random seeds (siphash.h) */
static void test_siphash(void)
{
    BlindPrf prf;

    /* The reference test vector: key 00..0F, message 00..07 */
    assert(siphash24_u64(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL,
                         0x0706050403020100ULL) == 0x93F5F5799A932462ULL);

    /* SipHash-2-4 with the key (seed, 0) of the counter 0, 1, 2... */
    blind_prf_init(&prf, 0);
    assert(blind_prf_next(&prf) == 0xE849E8BB6FFE2567ULL);
    assert(blind_prf_next(&prf) == 0x8004C5A694105F5EULL);
    blind_prf_init(&prf, 1);
    assert(blind_prf_next(&prf) == 0x1CC1D069B22D7407ULL);
    assert(blind_prf_next(&prf) == 0x66B9B4D4603B2E62ULL);
    assert(prf.counter == 2);
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
static void test_batch_to_affine(const EcField *field)
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
        assert(ec_batch_to_affine(&ws, affine, proj, count) == 0);
        for (k=0; k<count; k++) {
            assert(fe_inv(&ws, zinv, proj + 3*k*NW + 2*NW) == 0);
            fe_mul(&ws, x, proj + 3*k*NW, zinv);
            assert(memcmp(x, affine + 2*k*NW, sizeof x) == 0);
            fe_mul(&ws, x, proj + 3*k*NW + NW, zinv);
            assert(memcmp(x, affine + 2*k*NW + NW, sizeof x) == 0);
        }
    }
    ec_ws_free(&ws);
}

/*
 * The field operations for all the sizes: the fixed-size code (3, 4, 6, 7
 * and 9 words on 64-bit targets) and the generic one (the other sizes),
 * against nat_mulmod() and nat_submod(), with random odd moduli. Also
 * with the output aliasing an input.
 */
static void test_field_sizes(void)
{
    size_t nw;

    for (nw=1; nw<=10; nw++) {
        EcField *field;
        Nat *n, *na, *nb, *expected;
        uint64_t a[10], b[10], am[10], bm[10], r[10];
        EcWs ws;
        unsigned t, i;

        assert(nat_new(&n, nw) == 0);
        assert(nat_new(&na, nw) == 0);
        assert(nat_new(&nb, nw) == 0);
        assert(nat_new(&expected, nw) == 0);
        for (i=0; i<nw; i++)
            n->w[i] = rnd();
        n->w[0] |= 1;
        n->w[nw-1] |= (uint64_t)1 << 63;
        if (nw % 2)
            n->w[nw-1] = ~(uint64_t)0;              /* the top word at its maximum */
        assert(ec_field_new(&field, n) == 0);
        assert(ec_ws_new(&ws, field) == 0);

        for (t=0; t<100; t++) {
            for (i=0; i<nw; i++) {
                a[i] = rnd();
                b[i] = rnd();
            }
            a[nw-1] %= n->w[nw-1];
            b[nw-1] %= n->w[nw-1];
            if (t == 0)
                memset(a, 0, nw*8);
            if (t == 1) {
                memcpy(a, n->w, nw*8);              /* n - 1 */
                memcpy(b, n->w, nw*8);
                a[0]--;
                b[0]--;
            }
            memcpy(na->w, a, nw*8);
            memcpy(nb->w, b, nw*8);
            fe_from_words(&ws, am, a);
            fe_from_words(&ws, bm, b);

            fe_mul(&ws, r, am, bm);
            fe_to_words(&ws, r, r);
            assert(nat_mulmod(expected, na, nb, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);

            /* In place, on either input */
            memcpy(r, am, nw*8);
            fe_mul(&ws, r, r, bm);
            fe_mul(&ws, r, bm, r);
            assert(nat_mulmod(expected, expected, nb, n) == 0);
            fe_to_words(&ws, r, r);
            assert(memcmp(r, expected->w, nw*8) == 0);

            fe_sqr(&ws, r, am);
            fe_to_words(&ws, r, r);
            assert(nat_mulmod(expected, na, na, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);
            memcpy(r, am, nw*8);
            fe_sqr(&ws, r, r);
            fe_to_words(&ws, r, r);
            assert(memcmp(r, expected->w, nw*8) == 0);

            /* a + b = a - (n - b) mod n */
            fe_add(&ws, r, a, b);
            assert(nat_sub(expected, n, nb) == 0);
            assert(nat_submod(expected, na, expected, n) == 0);
            if (t == 0 || words_is_zero(b, nw) == 0)
                assert(memcmp(r, expected->w, nw*8) == 0);
            {
                uint64_t nb_neg[10], r2[10];

                fe_neg(&ws, nb_neg, b);
                fe_sub(&ws, r2, a, nb_neg);
                assert(memcmp(r, r2, nw*8) == 0);
            }
            fe_sub(&ws, r, a, b);
            assert(nat_submod(expected, na, nb, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);
            memcpy(r, a, nw*8);
            fe_add(&ws, r, r, b);
            fe_sub(&ws, r, r, b);
            assert(memcmp(r, a, nw*8) == 0);
            fe_neg(&ws, r, a);
            fe_add(&ws, r, r, a);
            for (i=0; i<nw; i++)
                assert(r[i] == 0);
        }

        ec_ws_free(&ws);
        ec_field_free(field);
        nat_free(n);
        nat_free(na);
        nat_free(nb);
        nat_free(expected);
    }
}

/* ---------------------------------------------------------------- */
/* The primes of a special form (ec_special.h)                      */
/* ---------------------------------------------------------------- */

void red_p448(uint64_t *out, const uint64_t *t);
void red_p521(uint64_t *out, const uint64_t *t);

static const uint64_t sp448[7] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

static const uint64_t sp521[9] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1FF
};

/* red_p448 (nw = 7) or red_p521 (nw = 9) of t (2*nw words), against nat_divmod() */
static void check_reduction(size_t nw, const uint64_t *t)
{
    Nat *nt, *np, *nr;
    uint64_t out[9];

    assert(nat_new(&nt, 2*nw) == 0);
    assert(nat_new(&np, nw) == 0);
    assert(nat_new(&nr, nw) == 0);
    memcpy(nt->w, t, 2*nw*8);
    memcpy(np->w, nw == 7 ? sp448 : sp521, nw*8);
    assert(nat_divmod(NULL, nr, nt, np) == 0);
    if (nw == 7)
        red_p448(out, t);
    else
        red_p521(out, t);
    assert(memcmp(out, nr->w, nw*8) == 0);
    nat_free(nt);
    nat_free(np);
    nat_free(nr);
}

/* t (2*nw words) = a*b, with a and b of nw words */
static void wide_product(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t nw)
{
    Nat *na, *nb, *nt;

    assert(nat_new(&na, nw) == 0);
    assert(nat_new(&nb, nw) == 0);
    assert(nat_new(&nt, 2*nw) == 0);
    memcpy(na->w, a, nw*8);
    memcpy(nb->w, b, nw*8);
    assert(nat_mul(nt, na, nb) == 0);
    memcpy(t, nt->w, 2*nw*8);
    nat_free(na);
    nat_free(nb);
    nat_free(nt);
}

/*
 * The reductions on their own: any input below 2^896 for p448, and below
 * 2^1042 (the largest product) for p521, with the edge cases.
 */
static void test_special_reductions(void)
{
    uint64_t t[18], pm1[9], x[9];
    size_t nw, i;
    unsigned it;

    for (nw=7; nw<=9; nw+=2) {
        const uint64_t *p = nw == 7 ? sp448 : sp521;

        memcpy(pm1, p, nw*8);
        pm1[0]--;

        for (it=0; it<3000; it++) {
            for (i=0; i<2*nw; i++)
                t[i] = rnd();
            if (nw == 9) {
                t[16] &= 0x3FFFF;               /* t < 2^1042 */
                t[17] = 0;
            }
            switch (it) {
            case 0:                             /* 0 */
                memset(t, 0, sizeof t);
                break;
            case 1:                             /* p */
                memset(t, 0, sizeof t);
                memcpy(t, p, nw*8);
                break;
            case 2:                             /* p - 1 */
                memset(t, 0, sizeof t);
                memcpy(t, pm1, nw*8);
                break;
            case 3:                             /* (p - 1)^2, the largest product */
                wide_product(t, pm1, pm1, nw);
                break;
            case 4:                             /* p * (p - 1) */
                wide_product(t, p, pm1, nw);
                break;
            case 5:                             /* the largest input */
                memset(t, 0xFF, sizeof t);
                if (nw == 9) {
                    t[16] = 0x3FFFF;
                    t[17] = 0;
                }
                break;
            case 6:                             /* the top half only, all ones */
                memset(t, 0, sizeof t);
                if (nw == 7) {
                    memset(t + 7, 0xFF, 7*8);
                } else {
                    t[8] = ~(uint64_t)0x1FF;    /* hi = 2^521 - 1 */
                    memset(t + 9, 0xFF, 7*8);
                    t[16] = 0x3FFFF;
                }
                break;
            case 7:                             /* both halves at their maximum */
                memset(t, 0xFF, sizeof t);
                if (nw == 9) {
                    t[16] = 0x3FFFF;
                    t[17] = 0;
                } else {
                    t[3] = 0xFFFFFFFEFFFFFFFFULL;
                }
                break;
            case 8:                             /* 2^448 or 2^521: 2^224 + 1, or 1 */
                memset(t, 0, sizeof t);
                if (nw == 7)
                    t[7] = 1;
                else
                    t[8] = 0x200;
                break;
            default:
                if (it % 7 == 0)                /* the first half all ones */
                    memset(t, 0xFF, nw*8);
                if (it % 11 == 0)               /* bits 224..447 of the top half all ones */
                    for (i=10; i<14 && nw == 7; i++)
                        t[i] = ~(uint64_t)0;
                break;
            }
            check_reduction(nw, t);
        }

        /* Products of values near p, and of powers of two with values near them */
        for (it=0; it<64; it++) {
            uint64_t y[9];

            memset(x, 0, sizeof x);
            memcpy(y, pm1, nw*8);
            if (it < 32) {
                x[0] = 1;
                y[0] -= it;
            } else {
                size_t k = (it - 32) * (64*nw - 1) / 31;    /* a bit position below p */

                if (k >= (nw == 7 ? 448 : 521))
                    k = (nw == 7 ? 447 : 520);
                x[k/64] = (uint64_t)1 << (k % 64);
                memcpy(y, x, nw*8);
                y[0] -= 1;
                if (k == 0)
                    y[0] = 0;
            }
            wide_product(t, x, y, nw);
            check_reduction(nw, t);
            wide_product(t, pm1, y, nw);
            check_reduction(nw, t);
        }
    }
}

/*
 * The field operations with the primes of a special form (plain
 * representation), against nat_mulmod() and nat_submod().
 */
static void test_special_fields(void)
{
    size_t nw, i;

    for (nw=7; nw<=9; nw+=2) {
        const uint64_t *p = nw == 7 ? sp448 : sp521;
        EcField *field;
        EcWs ws;
        Nat *n, *two, *p_minus_2, *na, *nb, *expected;
        uint64_t a[9], b[9], am[9], bm[9], r[9];
        uint8_t buf[72], ab[72];
        size_t len = nw == 7 ? 56 : 66;
        unsigned t;

        assert(nat_new(&n, nw) == 0);
        assert(nat_new(&two, 1) == 0);
        assert(nat_new(&p_minus_2, nw) == 0);
        assert(nat_new(&na, nw) == 0);
        assert(nat_new(&nb, nw) == 0);
        assert(nat_new(&expected, nw) == 0);
        memcpy(n->w, p, nw*8);
        two->w[0] = 2;
        assert(nat_sub(p_minus_2, n, two) == 0);

        assert(ec_field_new(&field, n) == 0);
        assert(field->kind == (nw == 7 ? EC_FIELD_P448 : EC_FIELD_P521));
        assert(nat_cmp(field->p_minus_2, p_minus_2) == 0);
        assert(field->p_bits == (nw == 7 ? 448 : 521));
        assert(field->one[0] == 1);
        for (i=1; i<nw; i++)
            assert(field->one[i] == 0);
        assert(ec_ws_new(&ws, field) == 0);

        for (t=0; t<300; t++) {
            for (i=0; i<nw; i++) {
                a[i] = rnd();
                b[i] = rnd();
            }
            if (nw == 9) {
                a[8] &= 0x1FF;
                b[8] &= 0x1FF;
            }
            /* below p (p448: also fine, unless the value is p or more) */
            if (words_lt(a, p, nw) == 0)
                a[0] = 0;
            if (words_lt(b, p, nw) == 0)
                b[0] = 0;
            if (t == 0)
                memset(a, 0, nw*8);
            if (t == 1 || t == 2) {
                memcpy(a, p, nw*8);
                a[0]--;
                memcpy(b, a, nw*8);
                if (t == 2) {
                    b[0] = 1;
                    memset(b + 1, 0, (nw - 1)*8);
                }
            }
            memcpy(na->w, a, nw*8);
            memcpy(nb->w, b, nw*8);

            fe_from_words(&ws, am, a);
            fe_from_words(&ws, bm, b);
            /* plain representation */
            assert(memcmp(am, a, nw*8) == 0);

            fe_mul(&ws, r, am, bm);
            fe_to_words(&ws, r, r);
            assert(nat_mulmod(expected, na, nb, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);

            /* In place, on either input */
            memcpy(r, am, nw*8);
            fe_mul(&ws, r, r, bm);
            assert(memcmp(r, expected->w, nw*8) == 0);
            memcpy(r, bm, nw*8);
            fe_mul(&ws, r, am, r);
            assert(memcmp(r, expected->w, nw*8) == 0);

            fe_sqr(&ws, r, am);
            assert(nat_mulmod(expected, na, na, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);
            memcpy(r, am, nw*8);
            fe_sqr(&ws, r, r);
            assert(memcmp(r, expected->w, nw*8) == 0);

            fe_sub(&ws, r, am, bm);
            assert(nat_submod(expected, na, nb, n) == 0);
            assert(memcmp(r, expected->w, nw*8) == 0);
            fe_add(&ws, r, r, bm);
            assert(memcmp(r, am, nw*8) == 0);

            /* inv: a * 1/a = 1, and 1/0 = 0 */
            assert(fe_inv(&ws, r, am) == 0);
            if (t == 0) {
                assert(words_is_zero(r, nw));
            } else {
                fe_mul(&ws, r, r, am);
                assert(memcmp(r, field->one, nw*8) == 0);
            }

            /* bytes */
            for (i=0; i<len; i++)
                ab[i] = (uint8_t)(a[(len - 1 - i)/8] >> (8*((len - 1 - i) % 8)));
            assert(fe_from_bytes(r, &ws, ab, len, 0) == 0);
            assert(memcmp(r, am, nw*8) == 0);
            assert(fe_to_bytes(buf, len, &ws, am) == 0);
            assert(memcmp(buf, ab, len) == 0);
        }

        ec_ws_free(&ws);
        ec_field_free(field);
        nat_free(n);
        nat_free(two);
        nat_free(p_minus_2);
        nat_free(na);
        nat_free(nb);
        nat_free(expected);
    }
}

int main(void)
{
    EcField *field;
    Nat *n, *two, *p_minus_2;

    n = modulus();
    assert(nat_new(&two, 1) == 0);
    assert(nat_new(&p_minus_2, NW) == 0);
    two->w[0] = 2;
    assert(nat_sub(p_minus_2, n, two) == 0);
    assert(ec_field_new(&field, two) == ERR_VALUE);   /* even */
    assert(field == NULL);
    two->w[0] = 1;
    assert(ec_field_new(&field, two) == ERR_VALUE);   /* p - 2 < 0 */
    assert(field == NULL);
    two->w[0] = 2;
    assert(ec_field_new(&field, n) == 0);
    assert(nat_cmp(field->p_minus_2, p_minus_2) == 0);
    assert(field->p_bits == (size_t)nat_bit_length(n));

    test_ws(field);
    test_field(field, n);
    test_field_sizes();
    test_special_reductions();
    test_special_fields();
    test_conversions(field);
    test_random(field);
    test_siphash();
    test_sizes();
    test_table_select();
    test_batch_to_affine(field);

    ec_field_free(field);
    nat_free(n);
    nat_free(two);
    nat_free(p_minus_2);
    return 0;
}
