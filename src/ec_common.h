/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * What the elliptic curves on the nat library have in common (the NIST
 * curves in ec_nat.c, Ed448 in ed448.c, X448 in curve448.c):
 * the field, a workspace, field elements, and the
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
#include "siphash.h"

/* The window of the scalar multiplications, in bits (signed digits) */
#define EC_WINDOW 5
/* Points per window in a table: the multiples 1..16 (2^(EC_WINDOW-1)) */
#define EC_DIGITS 16
/* Random bits added to the scalar (k + r*order) */
#define EC_BLINDING_BITS 64

/*
 * The precomputed tables of the generator (NIST curves, Ed448) can be left
 * out with EC_NO_TABLES, to save memory: the generator is then multiplied
 * like any other point (about 4-5x slower).
 */
#if defined(EC_NO_TABLES)
#define EC_USE_TABLES 0
#else
#define EC_USE_TABLES 1
#endif

/* Temporary field elements in a workspace */
#define EC_WS_TEMPS 11

/*
 * The representation of the field elements, which depends on p (public):
 *  - EC_FIELD_MONT: Montgomery form, for any odd p;
 *  - EC_FIELD_P448: plain, for p = 2^448 - 2^224 - 1 (Ed448, X448);
 *  - EC_FIELD_P521: plain, for p = 2^521 - 1 (P-521).
 * The two primes of a special form have their own reduction, after a
 * full product (ec_special.h).
 */
typedef enum { EC_FIELD_MONT, EC_FIELD_P448, EC_FIELD_P521 } EcFieldKind;

/* The field of a curve (shared by all the operations: read only) */
typedef struct {
    /*
     * The Montgomery context of p. With EC_FIELD_MONT, it does all the
     * arithmetic. With the other kinds, only its scratchpads are used
     * (in the private copy of each workspace), by mul_wide() and
     * sqr_wide() on 32-bit targets, and for P-521 in the BMI2/ADX build.
     */
    MontCtx *m;
    EcFieldKind kind;
    size_t nw;              /* 64-bit words of a field element */
    uint64_t *one;          /* 1, in the representation of the field (nw words) */
    Nat *p_minus_2;         /* the exponent of the inversion (Fermat) */
    size_t p_bits;          /* the size of p */
} EcField;

/** The field of the odd prime p (at least 3) **/
int ec_field_new(EcField **out, const Nat *p);
void ec_field_free(EcField *f);

/*
 * The workspace of one operation: a private copy of the Montgomery
 * scratchpads (the constants of the field are shared), and temporaries.
 * With one workspace per operation, a curve can be used by several
 * threads at the same time.
 */
typedef struct {
    const EcField *f;
    MontCtx *m;
    size_t nw;
    uint64_t *buf;
    uint64_t *zero;
    uint64_t *t[EC_WS_TEMPS];
} EcWs;

int ec_ws_new(EcWs *ws, const EcField *field);
void ec_ws_free(EcWs *ws);

/*
 * Field elements: nw words, in the representation of the field (see
 * EcField), smaller than p. The outputs may alias the inputs.
 *
 * Montgomery form: on 64-bit targets, the sizes of the curves (3, 4, 6, 7
 * and 9 words) have their own unrolled code (ec_field.h); other sizes,
 * and 32-bit targets, use mont_mul(), mont_sqr(), mod_add() and mod_sub().
 */
void fe_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b);
void fe_sqr(EcWs *ws, uint64_t *out, const uint64_t *a);
void fe_add(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b);
void fe_sub(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b);
void fe_neg(EcWs *ws, uint64_t *out, const uint64_t *a);

static inline void fe_copy(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    memcpy(out, a, ws->nw*sizeof(uint64_t));
}

/** out = a^e, for a PUBLIC exponent e (not constant time in e) **/
void fe_pow_public(EcWs *ws, uint64_t *out, const uint64_t *a, const Nat *e);

/** out = 1/a (Fermat: a^(p-2)), and 0 for a = 0 **/
int fe_inv(EcWs *ws, uint64_t *out, const uint64_t *a);

/** out = the number x (x < p), in the representation of the field **/
void fe_from_words(EcWs *ws, uint64_t *out, const uint64_t *x);
/** out = the number that a stands for (smaller than p) **/
void fe_to_words(EcWs *ws, uint64_t *out, const uint64_t *a);

/**
 * out = the big-endian number in (len bytes).
 * If reduce is 0, the number must be smaller than p (ERR_VALUE otherwise);
 * if it is 1, it must be smaller than 2p, and it is reduced.
 */
int fe_from_bytes(uint64_t *out, EcWs *ws, const uint8_t *in, size_t len, int reduce);
/** The big-endian encoding of a (len bytes, at least the size of p) **/
int fe_to_bytes(uint8_t *out, size_t len, EcWs *ws, const uint64_t *a);

/** A random field element in [1, 2^(p_bits-1)) from the generator (siphash.h) **/
void fe_random(EcWs *ws, uint64_t *out, size_t p_bits, BlindPrf *prf);

/**
 * kb (k_words words) = (k mod order) + r*order, for the big-endian
 * scalar k (len bytes, any length). k_words must hold
 * bits(order) + EC_BLINDING_BITS bits.
 */
int ec_blind_scalar(uint64_t *kb, size_t k_words, const Nat *order, const uint8_t *k, size_t len, uint64_t r);

/**
 * kw (k_words words) = k mod order, for the big-endian scalar k (len bytes,
 * any length), which is PUBLIC; the number of windows that it needs
 * goes into *windows (at most the one of a blinded scalar).
 */
int ec_public_scalar(uint64_t *kw, size_t k_words, size_t *windows, const Nat *order, const uint8_t *k, size_t len);

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
int ec_batch_to_affine(EcWs *ws, uint64_t *affine, const uint64_t *proj, size_t count);

/* ---------------------------------------------------------------- */
/* Curves with points in projective coordinates (X:Y:Z):            */
/* the NIST curves (ec_nat.c) and Ed448 (ed448.c)                   */
/* ---------------------------------------------------------------- */

typedef struct EcGroup EcGroup;

/** (x3:y3:z3) = (x1:y1:z1) + (x2:y2:z2) (complete formulas); the output may be an input **/
typedef void (*EcPointAddFunc)(EcWs *ws, const EcGroup *g,
                               uint64_t *x3, uint64_t *y3, uint64_t *z3,
                               const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                               const uint64_t *x2, const uint64_t *y2, const uint64_t *z2);
/**
 * (x3:y3:z3) = (x1:y1:z1) + (x2, y2), with the second point affine (not
 * the neutral point, but its result may be discarded); the output may be
 * the first input
 */
typedef void (*EcPointAddAffineFunc)(EcWs *ws, const EcGroup *g,
                                     uint64_t *x3, uint64_t *y3, uint64_t *z3,
                                     const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                                     const uint64_t *x2, const uint64_t *y2);
/** (x3:y3:z3) = 2*(x1:y1:z1); the output may be the input **/
typedef void (*EcPointDoubleFunc)(EcWs *ws, const EcGroup *g,
                                  uint64_t *x3, uint64_t *y3, uint64_t *z3,
                                  const uint64_t *x1, const uint64_t *y1, const uint64_t *z1);
/** 1 if (x:y:z) is a point of the curve, 0 otherwise **/
typedef uint64_t (*EcPointOnCurveFunc)(EcWs *ws, const EcGroup *g,
                                       const uint64_t *x, const uint64_t *y, const uint64_t *z);
/** (x:y:z) = k*(x:y:z), for a PUBLIC scalar kw over its lowest windows (variable base) **/
typedef int (*EcPointMulPublicFunc)(EcWs *ws, const EcGroup *g, uint64_t *x, uint64_t *y, uint64_t *z,
                                    const uint64_t *kw, size_t windows);

/*
 * A curve, and the group of its points (constants only, so that it can be
 * used by several threads at the same time).
 */
struct EcGroup {
    size_t nw;              /* 64-bit words of a field element */
    size_t len;             /* bytes of an encoded coordinate */
    EcField *field;         /* the field: arithmetic modulo p */
    uint64_t *param;        /* the constant of the formulas: b (NIST curves), d (Ed448) */
    uint64_t *gx, *gy;      /* the generator G (affine, field elements) */
    Nat *order;             /* the scalars are reduced and blinded modulo it: the order
                               of the whole group (n for the NIST curves, 4n for Ed448) */
    size_t k_words;         /* 64-bit words of a blinded scalar */
    size_t windows;         /* windows of a blinded scalar */
    uint64_t *g_table;      /* windows*EC_DIGITS affine points, x then y:
                               entry j of window i is (j+1) * 32^i * G */
    /*
     * Edwards curve: the neutral point is (0:1:1), and -(X:Y:Z) = (-X:Y:Z).
     * Otherwise: the point at infinity is (0:1:0), and -(X:Y:Z) = (X:-Y:Z).
     */
    int edwards;
    EcPointAddFunc add;
    EcPointAddAffineFunc add_affine;
    EcPointDoubleFunc dbl;
    EcPointOnCurveFunc on_curve;
    EcPointMulPublicFunc mul_public;    /* faster code for public scalars, or NULL */
};

/*
 * A point in projective coordinates (X:Y:Z), as field elements.
 * It can be freed after its group (nw is a copy).
 */
typedef struct {
    const EcGroup *g;
    size_t nw;
    uint64_t *x, *y, *z;
} EcPoint;

/**
 * Set up g, whose functions (and the flag edwards) are already set: the
 * field p, the constant param of the formulas, the generator (gx, gy) of
 * prime order n, all big-endian and len bytes long. The scalars are taken
 * modulo n * 2^cofactor_bits. Also compute the tables of the generator.
 * ERR_EC_POINT if the generator is not on the curve.
 */
int ec_group_init(EcGroup *g, const uint8_t *p, const uint8_t *param, const uint8_t *n,
                  unsigned cofactor_bits, const uint8_t *gx, const uint8_t *gy, size_t len);
/** Free what ec_group_init() allocated (not g itself) **/
void ec_group_clear(EcGroup *g);

/** (x:y:z) = the neutral point: (0:1:1) for an Edwards curve, (0:1:0) otherwise **/
void ec_point_set_neutral(const EcGroup *g, uint64_t *x, uint64_t *y, uint64_t *z);
/** A new point (X, Y, Z all zero), or NULL **/
EcPoint *ec_point_alloc(const EcGroup *g);
void ec_point_free(EcPoint *p);
int ec_point_clone(EcPoint **out, const EcPoint *p);
/** The affine coordinates (big-endian, len bytes each, at least g->len) **/
int ec_point_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPoint *p);
/** 0 if the two points are equal, ERR_VALUE if they are not (only that fact leaks) **/
int ec_point_cmp(const EcPoint *a, const EcPoint *b);
int ec_point_neg(EcPoint *p);
int ec_point_double(EcPoint *p);
/** a = a + b **/
int ec_point_add(EcPoint *a, const EcPoint *b);
/**
 * p = k*p, for the big-endian scalar k (len bytes, any length), which can
 * be secret: it is blinded with the random seed, and so are the coordinates.
 * With the generator, the tables are used. The result is checked to be on
 * the curve (ERR_EC_POINT otherwise).
 */
int ec_point_scalar(EcPoint *p, const uint8_t *k, size_t len, uint64_t seed);
/** p = k*p, for a PUBLIC scalar k: no blinding, and the running time depends on k **/
int ec_point_scalar_public(EcPoint *p, const uint8_t *k, size_t len);

#endif
