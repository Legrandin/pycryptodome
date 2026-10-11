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
    if (NULL == f->one) {
        res = ERR_MEMORY;
        goto fail;
    }

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
    free(f);
}

void ec_field_from_words(EcField *f, uint64_t *out, const uint64_t *x)
{
    if (EC_FIELD_MONT == f->kind)
        mont_to(out, x, f->m);
    else
        memmove(out, x, f->nw*sizeof(uint64_t));
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

int fe_inv(EcWs *ws, uint64_t *out, const uint64_t *a, const Nat *p_minus_2)
{
    if (EC_FIELD_MONT == ws->f->kind)
        return mont_pow(out, a, p_minus_2, (size_t)nat_bit_length(p_minus_2), ws->m);
    fe_pow_public(ws, out, a, p_minus_2);
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
        out[i] = ec_next_random(state);
    /* Fewer bits than p, and not zero */
    for (i=(p_bits - 1)/64 + 1; i<nw; i++)
        out[i] = 0;
    out[(p_bits - 1)/64] &= ((uint64_t)1 << ((p_bits - 1) % 64)) - 1;
    out[0] |= 1;
}

/* ---------------------------------------------------------------- */
/* Scalars                                                          */
/* ---------------------------------------------------------------- */

uint64_t ec_next_random(uint64_t *state)
{
    uint64_t z;

    *state += 0x9E3779B97F4A7C15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

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

int ec_batch_to_affine(EcWs *ws, uint64_t *affine, const uint64_t *proj, size_t count, const Nat *p_minus_2)
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
    res = fe_inv(ws, inv, prefix + (count-1)*nw, p_minus_2);
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
