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

/* ---------------------------------------------------------------- */
/* Workspace                                                        */
/* ---------------------------------------------------------------- */

int ec_ws_new(EcWs *ws, const MontCtx *field)
{
    unsigned i;

    memset(ws, 0, sizeof *ws);
    ws->nw = field->nw;
    if (mont_ctx_new_private(&ws->m, field))
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

int fe_inv(EcWs *ws, uint64_t *out, const uint64_t *a, const Nat *p_minus_2)
{
    return mont_pow(out, a, p_minus_2, (size_t)nat_bit_length(p_minus_2), ws->m);
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
    mont_to(out, x->w, ws->m);

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
    mont_from(x.w, a, ws->m);
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
