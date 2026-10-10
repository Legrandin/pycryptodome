/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * What the elliptic curves on the nat library have in common (the NIST
 * curves in ec_nat.c, Ed448 in ed448.c, X448 in curve448.c):
 * a workspace, field elements in Montgomery form, and the
 * side-channel countermeasures of the scalar multiplications (blinding,
 * signed windows, full table scans, randomized coordinates).
 *
 * All the functions are constant time, except where a parameter is
 * documented as public.
 */

#ifndef EC_COMMON_H
#define EC_COMMON_H

#include <string.h>

#include "common.h"
#include "nat.h"

/* The window of the scalar multiplications, in bits (signed digits) */
#define EC_WINDOW 5
/* Points per window in a table: the multiples 1..16 (2^(EC_WINDOW-1)) */
#define EC_DIGITS 16
/* Random bits added to the scalar (k + r*order) */
#define EC_BLINDING_BITS 64

/* Temporary field elements in a workspace */
#define EC_WS_TEMPS 11

/*
 * The workspace of one operation: a private copy of the Montgomery
 * scratchpads (the constants of the field are shared), and temporaries.
 * With one workspace per operation, a curve can be used by several
 * threads at the same time.
 */
typedef struct {
    MontCtx *m;
    size_t nw;
    uint64_t *buf;
    uint64_t *zero;
    uint64_t *t[EC_WS_TEMPS];
} EcWs;

int ec_ws_new(EcWs *ws, const MontCtx *field);
void ec_ws_free(EcWs *ws);

/*
 * Field elements: nw words, in Montgomery form, smaller than p.
 * The outputs may alias the inputs.
 */
static inline void fe_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mont_mul(out, a, b, ws->m);
}

static inline void fe_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    mont_sqr(out, a, ws->m);
}

static inline void fe_add(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mod_add(out, a, b, ws->m->n, ws->nw);
}

static inline void fe_sub(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    mod_sub(out, a, b, ws->m->n, ws->nw);
}

static inline void fe_neg(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    mod_sub(out, ws->zero, a, ws->m->n, ws->nw);
}

static inline void fe_copy(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    memcpy(out, a, ws->nw*sizeof(uint64_t));
}

/** out = 1/a (Fermat: a^(p-2)), and 0 for a = 0 **/
int fe_inv(EcWs *ws, uint64_t *out, const uint64_t *a, const Nat *p_minus_2);

/**
 * out (Montgomery form) = the big-endian number in (len bytes).
 * If reduce is 0, the number must be smaller than p (ERR_VALUE otherwise);
 * if it is 1, it must be smaller than 2p, and it is reduced.
 */
int fe_from_bytes(uint64_t *out, EcWs *ws, const uint8_t *in, size_t len, int reduce);
/** The big-endian encoding of a (len bytes, at least the size of p) **/
int fe_to_bytes(uint8_t *out, size_t len, EcWs *ws, const uint64_t *a);

/** A random field element in [1, 2^(p_bits-1)) from the generator state **/
void fe_random(EcWs *ws, uint64_t *out, size_t p_bits, uint64_t *state);

/** A simple generator to expand a random seed (splitmix64) **/
uint64_t ec_next_random(uint64_t *state);

/**
 * kb (k_words words) = (k mod order) + r*order, for the big-endian
 * scalar k (len bytes, any length). k_words must hold
 * bits(order) + EC_BLINDING_BITS bits.
 */
int ec_blind_scalar(uint64_t *kb, size_t k_words, const Nat *order, const uint8_t *k, size_t len, uint64_t r);

/** The number of windows for a blinded scalar, for an order of order_bits bits **/
size_t ec_windows(size_t order_bits);
/** The number of words of a blinded scalar, for an order of order_bits bits **/
size_t ec_k_words(size_t order_bits);

/** count bits of k (kw words), from position pos (public) **/
uint64_t ec_get_bits(const uint64_t *k, size_t kw, size_t pos, unsigned count);

/**
 * The signed digit i of k (window i is public), in [-16, 16]: *sign is 1
 * for a negative digit, *digit is its absolute value.
 * k = sum of digit_i * 32^i (Booth recoding).
 */
void ec_booth_digit(const uint64_t *k, size_t kw, size_t i, uint64_t *sign, uint64_t *digit);

/**
 * out (entry_words words) = entry index of the table (entries entries of
 * entry_words words), or zero if index >= entries. The whole table is
 * read, whatever the index.
 */
void ec_table_select(uint64_t *out, const uint64_t *table, size_t entries, size_t entry_words, uint64_t index);

/**
 * Convert count projective points (X, Y, Z: 3*nw words each, with Z != 0)
 * to affine points (x, y: 2*nw words each), with a single inversion
 * (Montgomery's trick). For public points only (the tables).
 */
int ec_batch_to_affine(EcWs *ws, uint64_t *affine, const uint64_t *proj, size_t count, const Nat *p_minus_2);

#endif
