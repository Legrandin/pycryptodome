/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * What the elliptic curves on the nat library have in common.
 * See ec_common.h.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "ec_common.h"
#include "ec_field.h"
#include "ec_special.h"
#include "splitmix64.h"

/* ---------------------------------------------------------------- */
/* Field and workspace                                              */
/* ---------------------------------------------------------------- */

int ec_field_new(EcField **out, const Nat *p)
{
    EcField *f;
    int res;

    *out = f = (EcField*)calloc(1, sizeof(EcField));
    if (NULL == f)
        return ERR_MEMORY;

    res = mont_ctx_new(&f->m, p);
    if (res)
        goto fail;
    f->nw = p->nw;
    f->one = nat_words_alloc(f->nw);
    f->p_minus_2 = nat_alloc(f->nw);
    if (NULL == f->one || NULL == f->p_minus_2) {
        res = ERR_MEMORY;
        goto fail;
    }

    /* p - 2 (ERR_VALUE for p = 1) */
    f->p_minus_2->w[0] = 2;
    res = nat_sub(f->p_minus_2, p, f->p_minus_2);
    if (res)
        goto fail;
    f->p_bits = (size_t)nat_bit_length(p);

    /* p is public */
    f->kind = EC_FIELD_MONT;
    if (P448_WORDS == f->nw && words_eq(p->w, ec_p448, P448_WORDS))
        f->kind = EC_FIELD_P448;
    if (P521_WORDS == f->nw && words_eq(p->w, ec_p521, P521_WORDS))
        f->kind = EC_FIELD_P521;

    if (EC_FIELD_MONT == f->kind)
        memcpy(f->one, f->m->one, f->nw*sizeof(uint64_t));
    else
        f->one[0] = 1;
    return 0;

fail:
    ec_field_free(f);
    *out = NULL;
    return res;
}

void ec_field_free(EcField *f)
{
    if (NULL == f)
        return;
    mont_ctx_free(f->m);
    nat_words_free(f->one, f->nw);
    nat_free(f->p_minus_2);
    free(f);
}

int ec_ws_new(EcWs *ws, const EcField *field)
{
    unsigned i;

    memset(ws, 0, sizeof *ws);
    ws->f = field;
    ws->nw = field->nw;
    if (mont_ctx_new_private(&ws->m, field->m))
        return ERR_MEMORY;
    ws->buf = nat_words_alloc((EC_WS_TEMPS + 1)*ws->nw);
    if (NULL == ws->buf) {
        mont_ctx_free_private(ws->m);
        return ERR_MEMORY;
    }
    for (i=0; i<EC_WS_TEMPS; i++)
        ws->t[i] = ws->buf + i*ws->nw;
    ws->zero = ws->buf + EC_WS_TEMPS*ws->nw;
    return 0;
}

void ec_ws_free(EcWs *ws)
{
    mont_ctx_free_private(ws->m);
    nat_words_free(ws->buf, (EC_WS_TEMPS + 1)*ws->nw);
}

/* ---------------------------------------------------------------- */
/* Field elements                                                   */
/* ---------------------------------------------------------------- */

#if !defined(NAT_32BIT)

/*
 * The size is public, and so is the switch. With BMI2 and ADX, P-521
 * (9 words) is faster with the MULX/ADX kernel of mont_mul().
 */
static void fe_mont_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    const uint64_t *n = ws->m->n;
    uint64_t m0 = ws->m->m0;

    switch (ws->nw) {
    case 3: fe_mont_mul_3(out, a, b, n, m0); break;
    case 4: fe_mont_mul_4(out, a, b, n, m0); break;
    case 6: fe_mont_mul_6(out, a, b, n, m0); break;
    case 7: fe_mont_mul_7(out, a, b, n, m0); break;
#if !defined(NAT_BMI2_ADX)
    case 9: fe_mont_mul_9(out, a, b, n, m0); break;
#endif
    default: mont_mul(out, a, b, ws->m); break;
    }
}

static void fe_mont_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    const uint64_t *n = ws->m->n;
    uint64_t m0 = ws->m->m0;

    switch (ws->nw) {
    case 3: fe_mont_sqr_3(out, a, n, m0); break;
    case 4: fe_mont_sqr_4(out, a, n, m0); break;
    case 6: fe_mont_sqr_6(out, a, n, m0); break;
    case 7: fe_mont_sqr_7(out, a, n, m0); break;
#if !defined(NAT_BMI2_ADX)
    case 9: fe_mont_sqr_9(out, a, n, m0); break;
#endif
    default: mont_sqr(out, a, ws->m); break;
    }
}

void fe_add(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    const uint64_t *n = ws->m->n;

    switch (ws->nw) {
    case 3: fe_mod_add_3(out, a, b, n); break;
    case 4: fe_mod_add_4(out, a, b, n); break;
    case 6: fe_mod_add_6(out, a, b, n); break;
    case 7: fe_mod_add_7(out, a, b, n); break;
    case 9: fe_mod_add_9(out, a, b, n); break;
    default: mod_add(out, a, b, n, ws->nw); break;
    }
}

void fe_sub(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    const uint64_t *n = ws->m->n;

    switch (ws->nw) {
    case 3: fe_mod_sub_3(out, a, b, n); break;
    case 4: fe_mod_sub_4(out, a, b, n); break;
    case 6: fe_mod_sub_6(out, a, b, n); break;
    case 7: fe_mod_sub_7(out, a, b, n); break;
    case 9: fe_mod_sub_9(out, a, b, n); break;
    default: mod_sub(out, a, b, n, ws->nw); break;
    }
}

#else

static void fe_mont_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mont_mul(out, a, b, ws->m);
}

static void fe_mont_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    mont_sqr(out, a, ws->m);
}

void fe_add(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mod_add(out, a, b, ws->m->n, ws->nw);
}

void fe_sub(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mod_sub(out, a, b, ws->m->n, ws->nw);
}

#endif /* NAT_32BIT */

/* The kind of field is public, and so is the switch */
void fe_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    switch (ws->f->kind) {
    case EC_FIELD_P448: fe_p448_mul(ws, out, a, b); break;
    case EC_FIELD_P521: fe_p521_mul(ws, out, a, b); break;
    default: fe_mont_mul(ws, out, a, b); break;
    }
}

void fe_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    switch (ws->f->kind) {
    case EC_FIELD_P448: fe_p448_sqr(ws, out, a); break;
    case EC_FIELD_P521: fe_p521_sqr(ws, out, a); break;
    default: fe_mont_sqr(ws, out, a); break;
    }
}

void fe_neg(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    fe_sub(ws, out, ws->zero, a);
}

#define FE_POW_WINDOW 4
#define FE_POW_MAX_WORDS 9

/**
 * out = a^e, for a public exponent e, with fe_mul() and fe_sqr()
 * (fixed windows of 4 bits; the table is indexed by public digits).
 */
void fe_pow_public(EcWs *ws, uint64_t *out, const uint64_t *a, const Nat *e)
{
    uint64_t table[1 << FE_POW_WINDOW][FE_POW_MAX_WORDS], acc[FE_POW_MAX_WORDS];
    const size_t nw = ws->nw;
    size_t bits, windows, i;
    unsigned j;

    fe_copy(ws, table[0], ws->f->one);
    fe_copy(ws, table[1], a);
    for (j=2; j < (1U << FE_POW_WINDOW); j++)
        fe_mul(ws, table[j], table[j-1], a);

    bits = (size_t)nat_bit_length(e);
    windows = (bits + FE_POW_WINDOW - 1) / FE_POW_WINDOW;
    fe_copy(ws, acc, ws->f->one);
    for (i=windows; i-- > 0;) {
        uint64_t digit = ec_get_bits(e->w, e->nw, i*FE_POW_WINDOW, FE_POW_WINDOW);

        if (i + 1 < windows)
            for (j=0; j<FE_POW_WINDOW; j++)
                fe_sqr(ws, acc, acc);
        if (digit)
            fe_mul(ws, acc, acc, table[digit]);
    }
    memcpy(out, acc, nw*sizeof(uint64_t));
}

int fe_inv(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    const Nat *e = ws->f->p_minus_2;

    if (EC_FIELD_MONT == ws->f->kind)
        return mont_pow(out, a, e, (size_t)nat_bit_length(e), ws->m);
    fe_pow_public(ws, out, a, e);
    return 0;
}

void fe_from_words(EcWs *ws, uint64_t *out, const uint64_t *x)
{
    if (EC_FIELD_MONT == ws->f->kind)
        mont_to(out, x, ws->m);
    else
        memmove(out, x, ws->nw*sizeof(uint64_t));
}

void fe_to_words(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    if (EC_FIELD_MONT == ws->f->kind)
        mont_from(out, a, ws->m);
    else
        memmove(out, a, ws->nw*sizeof(uint64_t));
}

int fe_from_bytes(uint64_t *out, EcWs *ws, const uint8_t *in, size_t len, int reduce)
{
    const size_t nw = ws->nw;
    Nat *x;
    uint64_t lt;
    int res;

    x = nat_alloc(nw);
    if (NULL == x)
        return ERR_MEMORY;
    res = nat_from_bytes(x, in, len, 0);
    if (res)
        goto cleanup;

    lt = words_lt(x->w, ws->m->n, nw);
    if (reduce) {
        /* x < 2p: one subtraction at most */
        words_cond_sub(ct_mask(lt ^ 1), x->w, ws->m->n, nw);
    } else if (ct_declassify(lt ^ 1)) {
        res = ERR_VALUE;
        goto cleanup;
    }
    fe_from_words(ws, out, x->w);

cleanup:
    nat_free(x);
    return res;
}

int fe_to_bytes(uint8_t *out, size_t len, EcWs *ws, const uint64_t *a)
{
    Nat x;
    int res;

    x.nw = ws->nw;
    x.w = nat_words_alloc(ws->nw);
    if (NULL == x.w)
        return ERR_MEMORY;
    fe_to_words(ws, x.w, a);
    res = nat_to_bytes(out, len, &x, 0);
    nat_words_free(x.w, ws->nw);
    return res;
}

void fe_random(EcWs *ws, uint64_t *out, size_t p_bits, uint64_t *state)
{
    const size_t nw = ws->nw;
    size_t i;

    for (i=0; i<nw; i++)
        out[i] = splitmix64_next(state);
    /* Fewer bits than p, and not zero */
    for (i=(p_bits - 1)/64 + 1; i<nw; i++)
        out[i] = 0;
    out[(p_bits - 1)/64] &= ((uint64_t)1 << ((p_bits - 1) % 64)) - 1;
    out[0] |= 1;
}

/* ---------------------------------------------------------------- */
/* Scalars                                                          */
/* ---------------------------------------------------------------- */

int ec_blind_scalar(uint64_t *kb, size_t k_words, const Nat *order, const uint8_t *k, size_t len, uint64_t r)
{
    Nat *kn = NULL, *kred = NULL, *rn = NULL, out;
    int res = ERR_MEMORY;

    kn = nat_alloc(len/8 + 1);
    kred = nat_alloc(order->nw);
    rn = nat_alloc(1);
    if (NULL == kn || NULL == kred || NULL == rn)
        goto cleanup;

    res = nat_from_bytes(kn, k, len, 0);
    if (res)
        goto cleanup;
    res = nat_divmod(NULL, kred, kn, order);
    if (res)
        goto cleanup;

    rn->w[0] = r;
    out.nw = k_words;
    out.w = kb;
    res = nat_muladd(&out, kred, order, rn);

cleanup:
    nat_free(kn);
    nat_free(kred);
    nat_free(rn);
    return res;
}

int ec_public_scalar(uint64_t *kw, size_t k_words, size_t *windows, const Nat *order, const uint8_t *k, size_t len)
{
    size_t bits;
    int res;

    /* k mod order (with r = 0, no blinding) */
    res = ec_blind_scalar(kw, k_words, order, k, len, 0);
    if (res)
        return res;

    /* The value is public: the loop can stop at its top bit */
    bits = 64*k_words;
    while (bits > 0 && ((kw[(bits-1)/64] >> ((bits-1) % 64)) & 1) == 0)
        bits--;

    /* The top digit of the Booth recoding needs a zero bit above */
    *windows = (bits + 1 + EC_WINDOW - 1) / EC_WINDOW;
    if (*windows == 0)
        *windows = 1;
    return 0;
}

size_t ec_k_words(size_t order_bits)
{
    return (order_bits + EC_BLINDING_BITS + 63) / 64;
}

size_t ec_windows(size_t order_bits)
{
    /* The top digit of the Booth recoding needs a zero bit above */
    return (order_bits + EC_BLINDING_BITS + 1 + EC_WINDOW - 1) / EC_WINDOW;
}

uint64_t ec_get_bits(const uint64_t *k, size_t kw, size_t pos, unsigned count)
{
    size_t word = pos / 64;
    unsigned shift = (unsigned)(pos % 64);
    uint64_t lo, hi;

    lo = word < kw ? k[word] >> shift : 0;
    hi = (shift && word + 1 < kw) ? k[word + 1] << (64 - shift) : 0;
    return (lo | hi) & (((uint64_t)1 << count) - 1);
}

/*
 * Booth recoding of windows of 5 bits, from the 6 bits 5i-1 .. 5i+4
 * (bit -1 is 0). Without branches (the scalar is secret).
 */
void ec_booth_digit(const uint64_t *k, size_t kw, size_t i, uint64_t *sign, uint64_t *digit)
{
    uint64_t v, m, d;

    if (i == 0)
        v = ec_get_bits(k, kw, 0, 5) << 1;
    else
        v = ec_get_bits(k, kw, EC_WINDOW*i - 1, 6);

    *sign = v >> 5;
    m = ct_mask(*sign);
    d = ((63 - v) & m) | (v & ~m);
    *digit = (d >> 1) + (d & 1);
}

void ec_table_select(uint64_t *out, const uint64_t *table, size_t entries, size_t entry_words, uint64_t index)
{
    size_t d, j;

    memset(out, 0, entry_words*sizeof(uint64_t));
    for (d=0; d<entries; d++) {
        uint64_t m = ct_mask(ct_eq(d, index));

        for (j=0; j<entry_words; j++)
            out[j] |= table[d*entry_words + j] & m;
    }
}

/* ---------------------------------------------------------------- */
/* Tables                                                           */
/* ---------------------------------------------------------------- */

int ec_batch_to_affine(EcWs *ws, uint64_t *affine, const uint64_t *proj, size_t count)
{
    const size_t nw = ws->nw;
    uint64_t *prefix, *inv, *zinv;
    size_t k;
    int res = ERR_MEMORY;

#define PX(k) (proj + (3*(k) + 0)*nw)
#define PY(k) (proj + (3*(k) + 1)*nw)
#define PZ(k) (proj + (3*(k) + 2)*nw)

    prefix = nat_words_alloc(count*nw);
    inv = nat_words_alloc(nw);
    zinv = nat_words_alloc(nw);
    if (!prefix || !inv || !zinv)
        goto cleanup;

    /* prefix[k] = Z_0 * ... * Z_k */
    fe_copy(ws, prefix, PZ(0));
    for (k=1; k<count; k++)
        fe_mul(ws, prefix + k*nw, prefix + (k-1)*nw, PZ(k));
    res = fe_inv(ws, inv, prefix + (count-1)*nw);
    if (res)
        goto cleanup;

    /* Backwards: 1/Z_k = inv * prefix[k-1], then inv = inv * Z_k */
    for (k=count; k-- > 0;) {
        uint64_t *x = affine + 2*k*nw;

        if (k > 0)
            fe_mul(ws, zinv, inv, prefix + (k-1)*nw);
        else
            fe_copy(ws, zinv, inv);
        fe_mul(ws, inv, inv, PZ(k));
        fe_mul(ws, x, PX(k), zinv);
        fe_mul(ws, x + nw, PY(k), zinv);
    }

#undef PX
#undef PY
#undef PZ

cleanup:
    nat_words_free(prefix, count*nw);
    nat_words_free(inv, nw);
    nat_words_free(zinv, nw);
    return res;
}

/* ---------------------------------------------------------------- */
/* Curves with points in projective coordinates (X:Y:Z)             */
/* ---------------------------------------------------------------- */

void ec_point_set_neutral(const EcGroup *g, uint64_t *x, uint64_t *y, uint64_t *z)
{
    const size_t nw = g->nw;

    memset(x, 0, nw*sizeof(uint64_t));
    memcpy(y, g->field->one, nw*sizeof(uint64_t));
    if (g->edwards)
        memcpy(z, g->field->one, nw*sizeof(uint64_t));
    else
        memset(z, 0, nw*sizeof(uint64_t));
}

/** The offset of the coordinate that a negation changes: X (Edwards) or Y **/
static size_t ec_neg_offset(const EcGroup *g)
{
    return g->edwards ? 0 : g->nw;
}

/*
 * (rx:ry:rz) = k * (px:py:pz), for any point (variable base), with the
 * scalar kb (g->k_words words) over its lowest windows.
 *
 * A table of the multiples 0P ... 16P (projective) is built, from a
 * randomized copy of P (coordinates multiplied by lambda); then, for each
 * window from the top: 5 doublings, a full scan of the table for the
 * digit, a conditional negation, and an addition. The output may be
 * the input.
 *
 * For a public scalar, windows can be fewer than for a blinded one.
 */
STATIC int ec_mul_var(EcWs *ws, const EcGroup *g,
                      uint64_t *rx, uint64_t *ry, uint64_t *rz,
                      const uint64_t *px, const uint64_t *py, const uint64_t *pz,
                      const uint64_t *kb, size_t windows, const uint64_t *lambda)
{
    const size_t nw = g->nw;
    const size_t entries = EC_DIGITS + 1;
    const size_t neg = ec_neg_offset(g);
    uint64_t *table, *acc, *sel, *t;
    size_t i, j, w;
    int res = ERR_MEMORY;

    table = nat_words_alloc(3*entries*nw);
    acc = nat_words_alloc(3*nw);
    sel = nat_words_alloc(3*nw);
    t = nat_words_alloc(nw);
    if (!table || !acc || !sel || !t)
        goto cleanup;

#define TX(j) (table + (3*(j) + 0)*nw)
#define TY(j) (table + (3*(j) + 1)*nw)
#define TZ(j) (table + (3*(j) + 2)*nw)

    /* T[0] = neutral, T[1] = P (randomized), T[j] = T[j-1] + P */
    ec_point_set_neutral(g, TX(0), TY(0), TZ(0));
    fe_mul(ws, TX(1), px, lambda);
    fe_mul(ws, TY(1), py, lambda);
    fe_mul(ws, TZ(1), pz, lambda);
    for (j=2; j<entries; j++)
        g->add(ws, g, TX(j), TY(j), TZ(j), TX(j-1), TY(j-1), TZ(j-1), TX(1), TY(1), TZ(1));

#undef TX
#undef TY
#undef TZ

    ec_point_set_neutral(g, acc, acc + nw, acc + 2*nw);

    for (w=windows; w-- > 0;) {
        uint64_t sign, digit;

        for (i=0; i<EC_WINDOW; i++)
            g->dbl(ws, g, acc, acc + nw, acc + 2*nw, acc, acc + nw, acc + 2*nw);

        ec_booth_digit(kb, g->k_words, w, &sign, &digit);
        ec_table_select(sel, table, entries, 3*nw, digit);

        /* Negative digit */
        fe_neg(ws, t, sel + neg);
        words_select(sel + neg, ct_mask(sign), t, sel + neg, nw);

        g->add(ws, g, acc, acc + nw, acc + 2*nw, acc, acc + nw, acc + 2*nw, sel, sel + nw, sel + 2*nw);
    }

    fe_copy(ws, rx, acc);
    fe_copy(ws, ry, acc + nw);
    fe_copy(ws, rz, acc + 2*nw);
    res = 0;

cleanup:
    nat_words_free(table, 3*entries*nw);
    nat_words_free(acc, 3*nw);
    nat_words_free(sel, 3*nw);
    nat_words_free(t, nw);
    return res;
}

/*
 * (rx:ry:rz) = k * G, with the precomputed tables (fixed base) and the
 * scalar kb (g->k_words words) over its lowest windows.
 *
 * For each window i: a full scan of its table for the digit, a
 * conditional negation, and an addition of the affine point. There are
 * no doublings. A zero digit selects no point: the addition is computed
 * anyway, and its result discarded with a mask. The accumulator starts as
 * the neutral point with randomized coordinates (multiplied by lambda).
 *
 * For a public scalar, windows can be fewer than for a blinded one.
 */
STATIC int ec_mul_g(EcWs *ws, const EcGroup *g,
                    uint64_t *rx, uint64_t *ry, uint64_t *rz,
                    const uint64_t *kb, size_t windows, const uint64_t *lambda)
{
    const size_t nw = g->nw;
    const size_t neg = ec_neg_offset(g);
    uint64_t *acc, *sum, *sel, *t;
    size_t i, w;
    int res = ERR_MEMORY;

    acc = nat_words_alloc(3*nw);
    sum = nat_words_alloc(3*nw);
    sel = nat_words_alloc(2*nw);
    t = nat_words_alloc(nw);
    if (!acc || !sum || !sel || !t)
        goto cleanup;

    ec_point_set_neutral(g, acc, acc + nw, acc + 2*nw);
    for (i=0; i<3; i++)
        fe_mul(ws, acc + i*nw, acc + i*nw, lambda);

    for (w=0; w<windows; w++) {
        const uint64_t *window = g->g_table + w*EC_DIGITS*2*nw;
        uint64_t sign, digit;

        ec_booth_digit(kb, g->k_words, w, &sign, &digit);

        /* Entry d of the window is (d+1)*32^w*G; digit 0 selects nothing */
        ec_table_select(sel, window, EC_DIGITS, 2*nw, digit - 1);

        fe_neg(ws, t, sel + neg);
        words_select(sel + neg, ct_mask(sign), t, sel + neg, nw);

        g->add_affine(ws, g, sum, sum + nw, sum + 2*nw, acc, acc + nw, acc + 2*nw, sel, sel + nw);
        words_select(acc, ct_mask(ct_z(digit)), acc, sum, 3*nw);
    }

    fe_copy(ws, rx, acc);
    fe_copy(ws, ry, acc + nw);
    fe_copy(ws, rz, acc + 2*nw);
    res = 0;

cleanup:
    nat_words_free(acc, 3*nw);
    nat_words_free(sum, 3*nw);
    nat_words_free(sel, 2*nw);
    nat_words_free(t, nw);
    return res;
}

/*
 * The tables of the generator: for each window i, the affine points
 * j * 32^i * G for j = 1..16. The data is public.
 */
STATIC int ec_build_g_table(EcWs *ws, EcGroup *g)
{
    const size_t nw = g->nw;
    const size_t count = g->windows*EC_DIGITS;
    uint64_t *proj, *base;
    size_t i, j, k;
    int res = ERR_MEMORY;

    g->g_table = nat_words_alloc(2*count*nw);
    proj = nat_words_alloc(3*count*nw);
    base = nat_words_alloc(3*nw);
    if (!g->g_table || !proj || !base)
        goto cleanup;

#define PX(k) (proj + (3*(k) + 0)*nw)
#define PY(k) (proj + (3*(k) + 1)*nw)
#define PZ(k) (proj + (3*(k) + 2)*nw)

    /* base = 32^i * G */
    fe_copy(ws, base, g->gx);
    fe_copy(ws, base + nw, g->gy);
    fe_copy(ws, base + 2*nw, g->field->one);

    for (i=0; i<g->windows; i++) {
        k = i*EC_DIGITS;
        memcpy(PX(k), base, 3*nw*sizeof(uint64_t));
        for (j=1; j<EC_DIGITS; j++)
            g->add(ws, g, PX(k+j), PY(k+j), PZ(k+j), PX(k+j-1), PY(k+j-1), PZ(k+j-1),
                   base, base + nw, base + 2*nw);
        /* 32 * base = 2 * (16 * base) */
        g->dbl(ws, g, base, base + nw, base + 2*nw, PX(k+15), PY(k+15), PZ(k+15));
    }

#undef PX
#undef PY
#undef PZ

    /* No Z is zero: the order of G is a prime larger than 16 */
    res = ec_batch_to_affine(ws, g->g_table, proj, count);

cleanup:
    nat_words_free(proj, 3*count*nw);
    nat_words_free(base, 3*nw);
    return res;
}

int ec_group_init(EcGroup *g, const uint8_t *p, const uint8_t *param, const uint8_t *n,
                  unsigned cofactor_bits, const uint8_t *gx, const uint8_t *gy, size_t len)
{
    Nat *pn = NULL, *nn = NULL;
    EcWs ws;
    int ws_ready = 0;
    size_t nw, order_bits;
    int res;

    if (len == 0 || len > 8*NAT_MAX_WORDS)
        return ERR_VALUE;
    g->nw = nw = (len + 7) / 8;
    g->len = len;

    res = ERR_MEMORY;
    pn = nat_alloc(nw);
    nn = nat_alloc(nw);
    g->order = nat_alloc(nw);
    g->param = nat_words_alloc(nw);
    g->gx = nat_words_alloc(nw);
    g->gy = nat_words_alloc(nw);
    if (!pn || !nn || !g->order || !g->param || !g->gx || !g->gy)
        goto cleanup;

    /* The field */
    res = nat_from_bytes(pn, p, len, 0);
    if (res)
        goto cleanup;
    res = ec_field_new(&g->field, pn);
    if (res)
        goto cleanup;

    /* The order of the whole group, and the size of the blinded scalars */
    res = nat_from_bytes(nn, n, len, 0);
    if (res)
        goto cleanup;
    res = nat_shl(g->order, nn, cofactor_bits);
    if (res)
        goto cleanup;
    order_bits = (size_t)nat_bit_length(g->order);
    g->k_words = ec_k_words(order_bits);
    g->windows = ec_windows(order_bits);

    res = ec_ws_new(&ws, g->field);
    if (res)
        goto cleanup;
    ws_ready = 1;

    res = fe_from_bytes(g->param, &ws, param, len, 0);
    if (res == 0)
        res = fe_from_bytes(g->gx, &ws, gx, len, 0);
    if (res == 0)
        res = fe_from_bytes(g->gy, &ws, gy, len, 0);
    if (res)
        goto cleanup;

    /* The generator must be on the curve */
    if (!g->on_curve(&ws, g, g->gx, g->gy, g->field->one)) {
        res = ERR_EC_POINT;
        goto cleanup;
    }

    if (EC_USE_TABLES)
        res = ec_build_g_table(&ws, g);

cleanup:
    if (ws_ready)
        ec_ws_free(&ws);
    nat_free(pn);
    nat_free(nn);
    return res;
}

void ec_group_clear(EcGroup *g)
{
    ec_field_free(g->field);
    nat_free(g->order);
    nat_words_free(g->param, g->nw);
    nat_words_free(g->gx, g->nw);
    nat_words_free(g->gy, g->nw);
    nat_words_free(g->g_table, 2*g->windows*EC_DIGITS*g->nw);
}

EcPoint *ec_point_alloc(const EcGroup *g)
{
    EcPoint *p;

    p = (EcPoint*)calloc(1, sizeof(EcPoint));
    if (NULL == p)
        return NULL;
    p->g = g;
    p->nw = g->nw;
    p->x = nat_words_alloc(3*g->nw);
    if (NULL == p->x) {
        free(p);
        return NULL;
    }
    p->y = p->x + g->nw;
    p->z = p->y + g->nw;
    return p;
}

void ec_point_free(EcPoint *p)
{
    if (NULL == p)
        return;
    nat_words_free(p->x, 3*p->nw);
    free(p);
}

int ec_point_clone(EcPoint **out, const EcPoint *p)
{
    if (!out || !p)
        return ERR_NULL;
    *out = ec_point_alloc(p->g);
    if (NULL == *out)
        return ERR_MEMORY;
    memcpy((*out)->x, p->x, 3*p->nw*sizeof(uint64_t));
    return 0;
}

int ec_point_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPoint *p)
{
    uint64_t *zinv;
    EcWs ws;
    int res;

    if (!x || !y || !p)
        return ERR_NULL;
    if (len < p->g->len)
        return ERR_NOT_ENOUGH_DATA;

    res = ec_ws_new(&ws, p->g->field);
    if (res)
        return res;
    zinv = ws.t[0];

    /* For the point at infinity (Z = 0), 1/Z is 0 (Fermat), and so are X/Z and Y/Z */
    res = fe_inv(&ws, zinv, p->z);
    if (res == 0) {
        fe_mul(&ws, ws.t[1], p->x, zinv);
        fe_mul(&ws, ws.t[2], p->y, zinv);
        res = fe_to_bytes(x, len, &ws, ws.t[1]);
    }
    if (res == 0)
        res = fe_to_bytes(y, len, &ws, ws.t[2]);

    ec_ws_free(&ws);
    return res;
}

int ec_point_cmp(const EcPoint *a, const EcPoint *b)
{
    uint64_t equal;
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->g != b->g)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->g->field))
        return ERR_MEMORY;

    /* X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1 */
    fe_mul(&ws, ws.t[0], a->x, b->z);
    fe_mul(&ws, ws.t[1], b->x, a->z);
    fe_mul(&ws, ws.t[2], a->y, b->z);
    fe_mul(&ws, ws.t[3], b->y, a->z);
    equal = words_eq(ws.t[0], ws.t[1], ws.nw) & words_eq(ws.t[2], ws.t[3], ws.nw);

    ec_ws_free(&ws);
    return ct_declassify(equal) ? 0 : ERR_VALUE;
}

int ec_point_neg(EcPoint *p)
{
    uint64_t *c;
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->g->field))
        return ERR_MEMORY;
    c = p->x + ec_neg_offset(p->g);
    fe_neg(&ws, c, c);
    ec_ws_free(&ws);
    return 0;
}

int ec_point_double(EcPoint *p)
{
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->g->field))
        return ERR_MEMORY;
    p->g->dbl(&ws, p->g, p->x, p->y, p->z, p->x, p->y, p->z);
    ec_ws_free(&ws);
    return 0;
}

int ec_point_add(EcPoint *a, const EcPoint *b)
{
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->g != b->g)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->g->field))
        return ERR_MEMORY;
    a->g->add(&ws, a->g, a->x, a->y, a->z, a->x, a->y, a->z, b->x, b->y, b->z);
    ec_ws_free(&ws);
    return 0;
}

/** 1 if p is the generator with Z = 1, 0 otherwise **/
static uint64_t ec_point_is_g(const EcPoint *p)
{
    const EcGroup *g = p->g;

    return words_eq(p->x, g->gx, g->nw) & words_eq(p->y, g->gy, g->nw) &
           words_eq(p->z, g->field->one, g->nw);
}

int ec_point_scalar(EcPoint *p, const uint8_t *k, size_t len, uint64_t seed)
{
    const EcGroup *g;
    uint64_t *kb, *lambda;
    uint64_t state = seed;
    EcWs ws;
    int res;

    if (!p || !k)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    g = p->g;

    res = ec_ws_new(&ws, g->field);
    if (res)
        return res;
    kb = nat_words_alloc(g->k_words);
    lambda = nat_words_alloc(g->nw);
    if (!kb || !lambda) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    /* The random values: r for the scalar, lambda for the coordinates */
    res = ec_blind_scalar(kb, g->k_words, g->order, k, len, splitmix64_next(&state));
    if (res)
        goto cleanup;
    fe_random(&ws, lambda, g->field->p_bits, &state);

    /* Only the fact that p is the generator leaks */
    if (EC_USE_TABLES && ct_declassify(ec_point_is_g(p)))
        res = ec_mul_g(&ws, g, p->x, p->y, p->z, kb, g->windows, lambda);
    else
        res = ec_mul_var(&ws, g, p->x, p->y, p->z, p->x, p->y, p->z, kb, g->windows, lambda);
    if (res)
        goto cleanup;

    if (!ct_declassify(g->on_curve(&ws, g, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    nat_words_free(kb, g->k_words);
    nat_words_free(lambda, g->nw);
    ec_ws_free(&ws);
    return res;
}

int ec_point_scalar_public(EcPoint *p, const uint8_t *k, size_t len)
{
    const EcGroup *g;
    uint64_t *kw;
    size_t windows;
    EcWs ws;
    int res;

    if (!p || !k)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    g = p->g;

    res = ec_ws_new(&ws, g->field);
    if (res)
        return res;
    kw = nat_words_alloc(g->k_words);
    if (!kw) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    res = ec_public_scalar(kw, g->k_words, &windows, g->order, k, len);
    if (res)
        goto cleanup;

    if (EC_USE_TABLES && ec_point_is_g(p))
        res = ec_mul_g(&ws, g, p->x, p->y, p->z, kw, windows, g->field->one);
    else if (g->mul_public)
        res = g->mul_public(&ws, g, p->x, p->y, p->z, kw, windows);
    else
        res = ec_mul_var(&ws, g, p->x, p->y, p->z, p->x, p->y, p->z, kw, windows, g->field->one);
    if (res)
        goto cleanup;

    if (!g->on_curve(&ws, g, p->x, p->y, p->z))
        res = ERR_EC_POINT;

cleanup:
    nat_words_free(kw, g->k_words);
    ec_ws_free(&ws);
    return res;
}
