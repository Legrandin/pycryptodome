/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SLH-DSA (FIPS 205): the functions that compute most of the hashes.
 *
 * Everything else is in Python (lib/Crypto/PublicKey/_fips205.py), which
 * calls these functions:
 *
 *  - slhdsa_thash():     F, H, T_l and PRF (Section 11)
 *  - slhdsa_chain():     chain (Algorithm 5)
 *  - slhdsa_xmss_node(): xmss_node (Algorithm 9), with wots_pkGen (Algorithm 6)
 *  - slhdsa_fors_node(): fors_node (Algorithm 15), with fors_skGen (Algorithm 14)
 *
 * Each function takes the hash family (SLHDSA_SHAKE or SLHDSA_SHA2), n
 * (16, 24 or 32 bytes) and lg_w (2, 3 or 4), which together select the
 * parameter set as far as these functions are concerned.
 * lg_w is 4 in FIPS 205, and 2 or 3 in the parameter sets of SP 800-230.
 * The seeds, the nodes and the outputs are always n bytes long,
 * and the addresses (ADRS) 32 bytes long (Section 4.2).
 *
 * The static functions follow the pseudocode of FIPS 205, with the same
 * names for the functions, the variables and the address member functions
 * (Table 1). A number in a comment at the end of a line is the line of the
 * algorithm that the function implements. The differences:
 *
 *  - PK.seed and SK.seed are not parameters: they are in the Context,
 *    together with the hash states after absorbing PK.seed;
 *  - the results go into an output buffer, the first parameter after ctx;
 *  - the AVX2 and SHA-NI code computes several hashes at once (see below),
 *    and it replaces some lines of the algorithms, as the comments say.
 *
 * SHAKE256 is keccak.c, SHA-256 and SHA-512 are SHA256.c and SHA512.c
 * (see slhdsa_sha2.h). This file is compiled three times:
 *
 *  - module _slhdsa: portable code;
 *  - module _slhdsa_shani (slhdsa_shani.c): SHA-256 uses the Intel SHA
 *    extensions, for the SHA2 parameter sets;
 *  - module _slhdsa_armv8 (slhdsa_armv8.c): SHA-256 uses the instructions
 *    of the ARMv8 Cryptography Extensions, for the SHA2 parameter sets
 *    (on other CPUs, such as the x86-64 half of a macOS universal2 build,
 *    it is the portable code);
 *  - module _slhdsa_avx2_bmi2 (slhdsa_avx2_bmi2.c): compiled for AVX2.
 *
 * In the last three, wots_pkGen computes several chains at once, and fors_node
 * several subtrees at once, one per lane (Context.lanes):
 *
 *  - SHA2 with SHA-NI or ARMv8: 4 lanes, with the rounds of the 4 SHA-256
 *    blocks interleaved through the SHA unit (hash_SHA2_compress_shani.c
 *    and hash_SHA2_compress_armv8.c);
 *  - SHAKE with AVX2: 4 lanes, with the 4-way Keccak of keccak_x4_avx2.c;
 *  - SHA2 with AVX2: 8 lanes, with the 8-way SHA-256 of sha256_x8_avx2.c.
 *
 * Only F, PRF and H (for SHA2: H for n = 16 only, SHA-512 otherwise)
 * use the lanes.
 */

#include "common.h"
#include "endianess.h"
#include "errors.h"

/* The ARMv8 instructions only exist on 64-bit ARM (see hash_SHA2_template.c) */
#if defined(SLHDSA_ARMV8) && !(defined(__aarch64__) || defined(_M_ARM64))
#undef SLHDSA_ARMV8
#endif

#define KECCAK_EMBEDDED
#include "keccak.c"

#ifdef SLHDSA_AVX2
#include "keccak_x4_avx2.c"
#include "sha256_x8_avx2.c"
#endif

#include "slhdsa_sha2.h"

/* slhdsa_shani.c includes this file with another module name */
#ifndef SLHDSA_MODULE
#define SLHDSA_MODULE slhdsa
#endif
FAKE_INIT(SLHDSA_MODULE)

/* The hash families, as _SHAKE and _SHA2 in _fips205.py */
typedef enum {
    SLHDSA_SHAKE = 0,           /* Section 11.1 */
    SLHDSA_SHA2 = 1             /* Section 11.2 */
} HashFamily;

/* The builds that compute several hashes at once, one per lane */
#if defined(SLHDSA_AVX2) || defined(SLHDSA_SHA_NI) || defined(SLHDSA_ARMV8)
#define SLHDSA_LANES
#endif

/* The largest number of lanes (SHA2 with AVX2) */
#define MAX_LANES       8

/*
 * ctx->lanes, in the functions that use the lanes (ctx->lanes > 1),
 * from the hash family as the hash functions choose their code:
 * so the compiler sees that all the lanes that they read are set
 * (with SHA-NI or ARMv8, only SHA2 uses the lanes)
 */
#if defined(SLHDSA_AVX2)
#define LANES(ctx)      ((ctx)->family == SLHDSA_SHAKE ? 4U : 8U)
#else
#define LANES(ctx)      4U
#endif

/* n, the length of the hashes in bytes, for NIST security categories 1, 3 and 5 */
#define N_CAT1          16
#define N_CAT3          24
#define N_CAT5          32
#define N_MAX           N_CAT5

/* SHA-256 and SHA-512 (Section 11.2) */
#define SHA256_BLOCK_LEN    64
#define SHA256_DIGEST_LEN   32
#define SHA512_BLOCK_LEN    128
#define SHA512_DIGEST_LEN   64

/* The largest len (Section 5), for n = 32 and lg_w = 2: len1 = 128, len2 = 5 */
#define LEN_MAX         133

/*
 * The largest h' and a of all parameter sets: 9 and 14 in FIPS 205 (Table 2),
 * 22 and 25 in SP 800-230 (Table 1)
 */
#define MAX_XMSS_HEIGHT 22
#define MAX_FORS_HEIGHT 25

/* The FORS leaves are less than k * 2^a (at most 12 * 2^25) */
#define MAX_FORS_LEAVES (1UL << 29)

/*
 * Addresses (Section 4.2)
 */

#define ADRS_LEN        32

typedef struct {
    uint8_t bytes[ADRS_LEN];
} ADRS;

/* The address types (Section 4.2) */
typedef enum {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    WOTS_PRF = 5,
    FORS_PRF = 6
} AddressType;

/* The offsets of the 4-byte words of an address that this file changes (Table 1) */
typedef enum {
    OFFSET_TYPE = 16,
    OFFSET_KEY_PAIR = 20,
    OFFSET_CHAIN = 24,          /* also the tree height */
    OFFSET_HASH = 28            /* also the tree index */
} AddressOffset;

static void set_word(ADRS *adrs, AddressOffset offset, uint32_t value)
{
    STORE_U32_BIG(adrs->bytes + offset, value);
}

/*
 * The member functions of Table 1, with the same names
 * (setTypeAndClear() is set_type_and_clear(), etc.).
 * The layer and tree addresses are set in Python.
 */

/* ADRS.setTypeAndClear(Y): set the type, and the final 12 bytes to zero */
static void set_type_and_clear(ADRS *adrs, AddressType Y)
{
    set_word(adrs, OFFSET_TYPE, (uint32_t)Y);
    memset(adrs->bytes + OFFSET_KEY_PAIR, 0, ADRS_LEN - OFFSET_KEY_PAIR);
}

/* ADRS.setKeyPairAddress(i) */
static void set_key_pair_address(ADRS *adrs, uint32_t i)
{
    set_word(adrs, OFFSET_KEY_PAIR, i);
}

/* ADRS.getKeyPairAddress() */
static uint32_t get_key_pair_address(const ADRS *adrs)
{
    return LOAD_U32_BIG(adrs->bytes + OFFSET_KEY_PAIR);
}

/* ADRS.setChainAddress(i) */
static void set_chain_address(ADRS *adrs, uint32_t i)
{
    set_word(adrs, OFFSET_CHAIN, i);
}

/* ADRS.setTreeHeight(z): the same word as the chain address */
static void set_tree_height(ADRS *adrs, uint32_t z)
{
    set_word(adrs, OFFSET_CHAIN, z);
}

/* ADRS.setHashAddress(i) */
static void set_hash_address(ADRS *adrs, uint32_t i)
{
    set_word(adrs, OFFSET_HASH, i);
}

/* ADRS.setTreeIndex(i): the same word as the hash address */
static void set_tree_index(ADRS *adrs, uint32_t i)
{
    set_word(adrs, OFFSET_HASH, i);
}

/* SHA2: the compressed address ADRS^c (Section 11.2, Figure 18) */
#define ADRSC_LEN       22

/* ADRS^c = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32] */
static void compress_adrs(uint8_t adrsc[ADRSC_LEN], const ADRS *adrs)
{
    adrsc[0] = adrs->bytes[3];
    memcpy(adrsc + 1, adrs->bytes + 8, 8);
    adrsc[9] = adrs->bytes[19];
    memcpy(adrsc + 10, adrs->bytes + 20, 12);
}

/*
 * The parameters and the seeds
 */

/*
 * What the hash functions need: the parameters, the seeds, and
 * the hash states after absorbing PK.seed.
 * For SHA2, PK.seed is padded with zeroes to a full block (64 bytes for
 * SHA-256, and 128 bytes for SHA-512, which only categories 3 and 5 use).
 */
typedef struct {
    HashFamily family;
    unsigned n;
    unsigned w;                 /* the Winternitz parameter, 2^lg_w */
    unsigned len;               /* the number of WOTS+ chains */
    unsigned lanes;             /* how many F, PRF and H at once: 1, 4 or 8 */
    unsigned lg_lanes;          /* log2(lanes) */
    const uint8_t *pk_seed;
    const uint8_t *sk_seed;     /* NULL if not needed */
    keccak_state *shake;
    sha256_hash_state *sha256;
    sha512_hash_state *sha512;  /* NULL if n = 16 */
} Context;

/* Free the hash states of a Context */
static void context_free(Context *ctx)
{
    keccak_destroy(ctx->shake);
    SHA256_destroy(ctx->sha256);
    SHA512_destroy(ctx->sha512);
}

/* gen_len2 (Algorithm 1): len2 (Equation 5.3) */
static unsigned gen_len2(unsigned n, unsigned lg_w)
{
    unsigned w, len1, max_checksum, len2, capacity;

    w = 1U << lg_w;                         /*  1 */
    len1 = (8*n + lg_w - 1) / lg_w;         /*  2 */
    max_checksum = len1 * (w - 1);          /*  3 */
    len2 = 1;                               /*  4 */
    capacity = w;                           /*  5 */
    while (capacity <= max_checksum) {      /*  6 */
        len2 = len2 + 1;                    /*  7 */
        capacity = capacity * w;            /*  8 */
    }
    return len2;                            /* 10 */
}

/*
 * Check the parameters and set up a Context, with the hash states
 * after absorbing PK.seed. sk_seed can be NULL if PRF is not needed.
 * On success, the Context must be freed with context_free().
 */
static int context_init(Context *ctx, unsigned family, size_t n, unsigned lg_w,
                        const uint8_t *pk_seed, const uint8_t *sk_seed)
{
    uint8_t block[SHA512_BLOCK_LEN];
    unsigned len1;
    int res;

    memset(ctx, 0, sizeof *ctx);

    if (NULL == pk_seed)
        return ERR_NULL;
    if (family != SLHDSA_SHAKE && family != SLHDSA_SHA2)
        return ERR_VALUE;
    if (n != N_CAT1 && n != N_CAT3 && n != N_CAT5)
        return ERR_VALUE;
    if (lg_w < 2 || lg_w > 4)
        return ERR_VALUE;

    /* Equations 5.1 to 5.4 */
    len1 = (unsigned)(8*n + lg_w - 1) / lg_w;
    ctx->family = (HashFamily)family;
    ctx->n = (unsigned)n;
    ctx->w = 1U << lg_w;
    ctx->len = len1 + gen_len2(ctx->n, lg_w);
    ctx->pk_seed = pk_seed;
    ctx->sk_seed = sk_seed;

    ctx->lg_lanes = 0;
#if defined(SLHDSA_AVX2)
    ctx->lg_lanes = ctx->family == SLHDSA_SHAKE ? 2 : 3;
#elif defined(SLHDSA_SHA_NI) || defined(SLHDSA_ARMV8)
    ctx->lg_lanes = ctx->family == SLHDSA_SHA2 ? 2 : 0;
#endif
    ctx->lanes = 1U << ctx->lg_lanes;

    if (ctx->family == SLHDSA_SHAKE) {
        res = keccak_init(&ctx->shake, 64, 24);
        if (res == 0)
            res = keccak_absorb(ctx->shake, pk_seed, n);
    } else {
        /* PK.seed || toByte(0, 64 - n), and toByte(0, 128 - n) for SHA-512 */
        memset(block, 0, sizeof block);
        memcpy(block, pk_seed, n);
        res = SHA256_init(&ctx->sha256);
        if (res == 0)
            res = SHA256_update(ctx->sha256, block, SHA256_BLOCK_LEN);
        if (res == 0 && n > N_CAT1) {     /* SHA-512 for categories 3 and 5 */
            res = SHA512_init(&ctx->sha512, SHA512_DIGEST_LEN);
            if (res == 0)
                res = SHA512_update(ctx->sha512, block, SHA512_BLOCK_LEN);
        }
    }

    if (res)
        context_free(ctx);
    return res;
}

/*
 * The hash functions (Section 11).
 * The tweakable hash functions F, H, T_l and PRF of FIPS 205 are
 * thash_F(), thash_H(), thash_T_l() and thash_PRF() (and the _lanes versions
 * of F, H and PRF, which compute ctx->lanes hashes at once).
 * They cannot fail on a Context from context_init().
 * In all of them, out can be the same buffer as M.
 */

/* SHAKE256(PK.seed || ADRS || M, 8n) (Section 11.1) */
static void hash_shake256(const Context *ctx, uint8_t *out, const ADRS *adrs,
                          const uint8_t *M, size_t M_len)
{
    keccak_state ks;

    keccak_copy(ctx->shake, &ks);
    keccak_absorb(&ks, adrs->bytes, ADRS_LEN);
    keccak_absorb(&ks, M, M_len);
    keccak_squeeze(&ks, out, ctx->n, 0x1F);
}

/* Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M)) (Section 11.2) */
static void hash_sha256(const Context *ctx, uint8_t *out, const ADRS *adrs,
                        const uint8_t *M, size_t M_len)
{
    sha256_hash_state hs;
    uint8_t adrsc[ADRSC_LEN];
    uint8_t digest[SHA256_DIGEST_LEN];

    compress_adrs(adrsc, adrs);
    SHA256_copy(ctx->sha256, &hs);
    SHA256_update(&hs, adrsc, ADRSC_LEN);
    SHA256_update(&hs, M, M_len);
    SHA256_digest(&hs, digest, sizeof digest);
    memcpy(out, digest, ctx->n);
}

/* Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRS^c || M)) (Section 11.2.2) */
static void hash_sha512(const Context *ctx, uint8_t *out, const ADRS *adrs,
                        const uint8_t *M, size_t M_len)
{
    sha512_hash_state hs;
    uint8_t adrsc[ADRSC_LEN];
    uint8_t digest[SHA512_DIGEST_LEN];

    compress_adrs(adrsc, adrs);
    SHA512_copy(ctx->sha512, &hs);
    SHA512_update(&hs, adrsc, ADRSC_LEN);
    SHA512_update(&hs, M, M_len);
    SHA512_digest(&hs, digest, sizeof digest);
    memcpy(out, digest, ctx->n);
}

/* F(PK.seed, ADRS, M_1), with an n-byte M_1: SHA-256 in all SHA2 categories */
static void thash_F(const Context *ctx, uint8_t *out, const ADRS *adrs, const uint8_t *M_1)
{
    if (ctx->family == SLHDSA_SHAKE)
        hash_shake256(ctx, out, adrs, M_1, ctx->n);
    else
        hash_sha256(ctx, out, adrs, M_1, ctx->n);
}

/*
 * T_l(PK.seed, ADRS, M_l), with an l*n-byte M_l:
 * SHA-256 in SHA2 category 1, SHA-512 in categories 3 and 5
 */
static void thash_T_l(const Context *ctx, uint8_t *out, const ADRS *adrs,
                      const uint8_t *M_l, size_t l)
{
    if (ctx->family == SLHDSA_SHAKE)
        hash_shake256(ctx, out, adrs, M_l, l * ctx->n);
    else if (ctx->n == N_CAT1)        /* SHA-256 for category 1 (Section 11.2) */
        hash_sha256(ctx, out, adrs, M_l, l * ctx->n);
    else
        hash_sha512(ctx, out, adrs, M_l, l * ctx->n);
}

/* H(PK.seed, ADRS, M_2), with a 2n-byte M_2: the same as T_2 */
static void thash_H(const Context *ctx, uint8_t *out, const ADRS *adrs, const uint8_t *M_2)
{
    thash_T_l(ctx, out, adrs, M_2, 2);
}

/* PRF(PK.seed, SK.seed, ADRS): the same as F with M_1 = SK.seed */
static void thash_PRF(const Context *ctx, uint8_t *out, const ADRS *adrs)
{
    thash_F(ctx, out, adrs, ctx->sk_seed);
}

#ifdef SLHDSA_AVX2

#define SHAKE256_RATE   136

/* The largest number of n-byte blocks in M for hash_shake256_x4() */
#define X4_L_MAX        2

/*
 * PK.seed || ADRS || M and the padding fit into one block:
 * the array has a negative size (a compilation error) otherwise
 */
typedef char x4_input_fits_one_block[(N_MAX + ADRS_LEN + X4_L_MAX * N_MAX < SHAKE256_RATE) ? 1 : -1];

/*
 * hash_shake256() for 4 addresses and 4 inputs M of l*n bytes each,
 * at once with AVX2.
 *
 * l is at most X4_L_MAX, so that PK.seed || ADRS || M and the padding
 * fit into one block: this is the case for F and PRF (l = 1) and H (l = 2),
 * but not for T_l.
 *
 * out[j] can be the same buffer as M[j].
 */
static void hash_shake256_x4(const Context *ctx, uint8_t *out[4], const ADRS adrs[4],
                             const uint8_t *M[4], unsigned l)
{
    uint8_t blocks[4][SHAKE256_RATE];
    const uint8_t *in[4];
    __m256i A[25];
    size_t M_len, len;
    unsigned j;

    assert(l >= 1 && l <= X4_L_MAX);
    if (l < 1 || l > X4_L_MAX)          /* also with NDEBUG: never overflow blocks */
        return;
    M_len = (size_t)l * ctx->n;
    len = ctx->n + ADRS_LEN + M_len;

    for (j = 0; j < 4; j++) {
        memset(blocks[j], 0, SHAKE256_RATE);
        memcpy(blocks[j], ctx->pk_seed, ctx->n);
        memcpy(blocks[j] + ctx->n, adrs[j].bytes, ADRS_LEN);
        memcpy(blocks[j] + ctx->n + ADRS_LEN, M[j], M_len);
        blocks[j][len] = 0x1F;
        blocks[j][SHAKE256_RATE - 1] |= 0x80;
        in[j] = blocks[j];
    }

    memset(A, 0, sizeof A);
    keccak_absorb_x4(A, in, SHAKE256_RATE / 8);
    keccak_function_x4(A, 24);
    keccak_extract_x4(A, out, ctx->n / 8);
}

#endif /* SLHDSA_AVX2 */

#ifdef SLHDSA_LANES

/* The number of lanes for SHA2: 8 with AVX2, 4 with SHA-NI or ARMv8 */
#ifdef SLHDSA_AVX2
#define SHA256_LANES    8
#else
#define SHA256_LANES    4
#endif

/*
 * The longest M for hash_sha256_lanes(): n bytes for F and PRF (at most 32),
 * and 2n bytes for H with n = 16 (H is SHA-512 for larger n)
 */
#define SHA256_LANES_M_MAX  N_MAX

/*
 * ADRS^c || M, the padding byte 0x80 and the 8-byte length fit into
 * the block after PK.seed: the array has a negative size (a compilation
 * error) otherwise
 */
typedef char sha256_lanes_input_fits_one_block[(ADRSC_LEN + SHA256_LANES_M_MAX + 1 + 8 <= SHA256_BLOCK_LEN) ? 1 : -1];

/*
 * hash_sha256() for SHA256_LANES (ctx->lanes) addresses and inputs M
 * of M_len bytes each, at once (with SHA-NI or ARMv8, the 4 SHA-256 rounds
 * are interleaved; with AVX2, the 8 blocks are in vectors).
 *
 * M_len is at most SHA256_LANES_M_MAX, so that ADRS^c || M and the padding
 * are one block, compressed from the state after PK.seed: this is the case
 * for F and PRF, and for H with n = 16, but not for T_l.
 *
 * out[j] can be the same buffer as M[j].
 */
static void hash_sha256_lanes(const Context *ctx, uint8_t *out[], const ADRS adrs[],
                              const uint8_t *M[], size_t M_len)
{
    uint8_t blocks[SHA256_LANES][SHA256_BLOCK_LEN];
    uint32_t h[SHA256_LANES][8];
    const uint32_t *h_in[SHA256_LANES];
    const uint8_t *in[SHA256_LANES];
    uint32_t *h_out[SHA256_LANES];
    uint64_t bits;
    unsigned j, t;

    assert(ctx->lanes == SHA256_LANES);
    assert(M_len <= SHA256_LANES_M_MAX && ctx->sha256->curlen == 0);
    if (M_len > SHA256_LANES_M_MAX)     /* also with NDEBUG: never overflow blocks */
        return;

    /* The length of PK.seed || toByte(0, 64 - n) || ADRS^c || M, in bits */
    bits = 8 * (uint64_t)(SHA256_BLOCK_LEN + ADRSC_LEN + M_len);

    for (j = 0; j < SHA256_LANES; j++) {
        memset(blocks[j], 0, SHA256_BLOCK_LEN);
        compress_adrs(blocks[j], &adrs[j]);
        memcpy(blocks[j] + ADRSC_LEN, M[j], M_len);
        blocks[j][ADRSC_LEN + M_len] = 0x80;
        STORE_U64_BIG(blocks[j] + SHA256_BLOCK_LEN - 8, bits);
        h_in[j] = ctx->sha256->h;
        h_out[j] = h[j];
        in[j] = blocks[j];
    }

#ifdef SLHDSA_AVX2
    sha256_compress_x8_avx2(h_in, h_out, in);
#else
    sha256_compress_blocks_x4(h_in, h_out, in);
#endif

    /* Trunc_n */
    for (j = 0; j < SHA256_LANES; j++) {
        for (t = 0; t < ctx->n / 4; t++)
            STORE_U32_BIG(out[j] + 4*t, h[j][t]);
    }
}

/* F() for ctx->lanes inputs at once */
static void thash_F_lanes(const Context *ctx, uint8_t *out[], const ADRS adrs[],
                          const uint8_t *M_1[])
{
#ifdef SLHDSA_AVX2
    if (ctx->family == SLHDSA_SHAKE) {
        hash_shake256_x4(ctx, out, adrs, M_1, 1);
        return;
    }
#endif
    hash_sha256_lanes(ctx, out, adrs, M_1, ctx->n);
}

/* H() for ctx->lanes inputs at once (SHA-512 is one at a time) */
static void thash_H_lanes(const Context *ctx, uint8_t *out[], const ADRS adrs[],
                          const uint8_t *M_2[])
{
    unsigned j;

#ifdef SLHDSA_AVX2
    if (ctx->family == SLHDSA_SHAKE) {
        hash_shake256_x4(ctx, out, adrs, M_2, 2);
        return;
    }
#endif
    if (ctx->n == N_CAT1) {
        hash_sha256_lanes(ctx, out, adrs, M_2, 2 * N_CAT1);
    } else {
        for (j = 0; j < LANES(ctx); j++)
            hash_sha512(ctx, out[j], &adrs[j], M_2[j], 2 * ctx->n);
    }
}

/* PRF() for ctx->lanes addresses at once */
static void thash_PRF_lanes(const Context *ctx, uint8_t *out[], const ADRS adrs[])
{
    const uint8_t *sk_seed[MAX_LANES];
    unsigned j;

    for (j = 0; j < LANES(ctx); j++)
        sk_seed[j] = ctx->sk_seed;
    thash_F_lanes(ctx, out, adrs, sk_seed);
}

#endif /* SLHDSA_LANES */

/*
 * WOTS+ (Section 5)
 */

/*
 * chain (Algorithm 5): F iterated s times on X, from step i.
 * The result (tmp) goes into out, which can be the same buffer as X.
 */
static void chain(const Context *ctx, uint8_t *out, const uint8_t *X,
                  unsigned i, unsigned s, ADRS *adrs)
{
    uint8_t *tmp = out;
    unsigned j;

    memmove(tmp, X, ctx->n);                    /* 1 */
    for (j = i; j < i + s; j++) {               /* 2 */
        set_hash_address(adrs, j);              /* 3 */
        thash_F(ctx, tmp, adrs, tmp);           /* 4 */
    }
}

#ifdef SLHDSA_LANES

/*
 * wots_chains() for the chains i to i + lanes - 1 at once.
 * The chains from len onwards do not exist: their lanes compute
 * a copy of the last chain, which is not written to out.
 * A lane whose chain has fewer steps than the others writes its
 * last steps into idle[] instead.
 */
static void wots_chains_lanes(const Context *ctx, uint8_t *out, unsigned i, const uint8_t *X,
                              const uint8_t start[], const uint8_t steps[],
                              const ADRS *sk_adrs, const ADRS *adrs)
{
    ADRS lane_sk_adrs[MAX_LANES], lane_adrs[MAX_LANES];
    uint8_t buf[MAX_LANES][N_MAX], idle[MAX_LANES][N_MAX];
    uint8_t *lane_buf[MAX_LANES], *lane_out[MAX_LANES];
    const uint8_t *lane_in[MAX_LANES];
    unsigned c[MAX_LANES];
    unsigned j, k, n, max_steps;

    n = ctx->n;
    assert(ctx->lanes == LANES(ctx));

    max_steps = 0;
    for (j = 0; j < LANES(ctx); j++) {
        c[j] = MIN(i + j, ctx->len - 1);
        lane_sk_adrs[j] = *sk_adrs;
        set_chain_address(&lane_sk_adrs[j], c[j]);              /* 5 */
        lane_adrs[j] = *adrs;
        set_chain_address(&lane_adrs[j], c[j]);                 /* 7 */
        lane_buf[j] = buf[j];
        lane_in[j] = buf[j];
        if (X != NULL)
            memcpy(buf[j], X + c[j]*n, n);
        max_steps = MAX(max_steps, steps[c[j]]);
    }

    if (X == NULL)
        thash_PRF_lanes(ctx, lane_buf, lane_sk_adrs);           /* 6 */

    /* 8: chain(X, start, steps, PK.seed, ADRS), in place */
    for (k = 0; k < max_steps; k++) {
        for (j = 0; j < LANES(ctx); j++) {
            set_hash_address(&lane_adrs[j], start[c[j]] + k);
            lane_out[j] = k < steps[c[j]] ? buf[j] : idle[j];
        }
        thash_F_lanes(ctx, lane_out, lane_adrs, lane_in);
    }

    for (j = 0; j < LANES(ctx) && i + j < ctx->len; j++)
        memcpy(out + (i + j)*n, buf[j], n);
}

#endif /* SLHDSA_LANES */

/*
 * The len chains of the WOTS+ key pair in ADRS (of type WOTS_HASH),
 * into out (len*n bytes, it can be X): chain i is
 * chain(X_i, start[i], steps[i], PK.seed, ADRS with chain address i),
 * where X_i is X[i], or the private value of the chain (lines 1 to 6
 * of wots_pkGen, Algorithm 6) if X is NULL.
 * This is lines 1 to 9 of wots_pkGen, lines 8 to 16 of wots_sign
 * (Algorithm 7) and lines 8 to 11 of wots_pkFromSig (Algorithm 8).
 * ADRS is not modified.
 */
static void wots_chains(const Context *ctx, uint8_t *out, const uint8_t *X,
                        const uint8_t start[], const uint8_t steps[], const ADRS *adrs)
{
    ADRS sk_adrs, chain_adrs;
    unsigned i, n;

    n = ctx->n;

    sk_adrs = *adrs;                                                    /*  1 */
    set_type_and_clear(&sk_adrs, WOTS_PRF);                             /*  2 */
    set_key_pair_address(&sk_adrs, get_key_pair_address(adrs));         /*  3 */
#ifdef SLHDSA_LANES
    if (ctx->lanes > 1) {
        /* Lines 4 to 9, one chain per lane */
        for (i = 0; i < ctx->len; i += ctx->lanes)
            wots_chains_lanes(ctx, out, i, X, start, steps, &sk_adrs, adrs);
        return;
    }
#endif
    for (i = 0; i < ctx->len; i++) {                                    /*  4 */
        if (X == NULL) {
            set_chain_address(&sk_adrs, i);                             /*  5 */
            thash_PRF(ctx, out + i*n, &sk_adrs);                        /*  6 */
        }
        chain_adrs = *adrs;
        set_chain_address(&chain_adrs, i);                              /*  7 */
        chain(ctx, out + i*n, X ? X + i*n : out + i*n, start[i], steps[i], &chain_adrs); /* 8 */
    }
}

/*
 * wots_pkGen (Algorithm 6): the WOTS+ public key pk for the key pair in ADRS
 * (of type WOTS_HASH).
 */
static void wots_pkgen(const Context *ctx, uint8_t *pk, ADRS *adrs)
{
    ADRS wotspk_adrs;
    uint8_t tmp[LEN_MAX * N_MAX];
    uint8_t start[LEN_MAX], steps[LEN_MAX];

    /* 1 to 9: tmp[i] = chain(sk, 0, w - 1, PK.seed, ADRS) */
    memset(start, 0, sizeof start);
    memset(steps, (int)(ctx->w - 1), sizeof steps);
    wots_chains(ctx, tmp, NULL, start, steps, adrs);

    wotspk_adrs = *adrs;                                                /* 10 */
    set_type_and_clear(&wotspk_adrs, WOTS_PK);                          /* 11 */
    set_key_pair_address(&wotspk_adrs, get_key_pair_address(adrs));     /* 12 */
    thash_T_l(ctx, pk, &wotspk_adrs, tmp, ctx->len);                    /* 13 */
}

/*
 * XMSS (Section 6)
 */

/*
 * xmss_node (Algorithm 9): the root node of the XMSS subtree of height z
 * whose leftmost leaf is i * 2^z.
 */
static void xmss_node(const Context *ctx, uint8_t *node, uint32_t i, unsigned z,
                      ADRS *adrs)
{
    uint8_t lnode_rnode[2 * N_MAX];
    uint8_t *lnode = lnode_rnode;
    uint8_t *rnode = lnode_rnode + ctx->n;

    if (z == 0) {                                       /*  1 */
        set_type_and_clear(adrs, WOTS_HASH);            /*  2 */
        set_key_pair_address(adrs, i);                  /*  3 */
        wots_pkgen(ctx, node, adrs);                    /*  4 */
    } else {                                            /*  5 */
        xmss_node(ctx, lnode, 2*i, z - 1, adrs);        /*  6 */
        xmss_node(ctx, rnode, 2*i + 1, z - 1, adrs);    /*  7 */
        set_type_and_clear(adrs, TREE);                 /*  8 */
        set_tree_height(adrs, z);                       /*  9 */
        set_tree_index(adrs, i);                        /* 10 */
        thash_H(ctx, node, adrs, lnode_rnode);          /* 11 */
    }
}

/*
 * FORS (Section 8)
 */

/*
 * fors_skGen (Algorithm 14): the FORS private value idx, for the key pair
 * in ADRS (of type FORS_TREE).
 */
static void fors_skgen(const Context *ctx, uint8_t *sk, const ADRS *adrs, uint32_t idx)
{
    ADRS sk_adrs;

    sk_adrs = *adrs;                                                /* 1 */
    set_type_and_clear(&sk_adrs, FORS_PRF);                         /* 2 */
    set_key_pair_address(&sk_adrs, get_key_pair_address(adrs));     /* 3 */
    set_tree_index(&sk_adrs, idx);                                  /* 4 */
    thash_PRF(ctx, sk, &sk_adrs);                                   /* 5 */
}

#ifdef SLHDSA_LANES

/*
 * Lines 9 to 11 of fors_node (Algorithm 15): the node i of height z,
 * from lnode || rnode.
 */
static void fors_parent(const Context *ctx, uint8_t *node, uint32_t i, unsigned z,
                        const uint8_t *lnode_rnode, ADRS *adrs)
{
    set_tree_height(adrs, z);                   /*  9 */
    set_tree_index(adrs, i);                    /* 10 */
    thash_H(ctx, node, adrs, lnode_rnode);      /* 11 */
}

/*
 * fors_node (Algorithm 15) for the ctx->lanes adjacent subtrees of height z
 * whose leftmost leaves are (i + j) * 2^z, for j = 0 to lanes - 1, at once:
 * their root nodes go into node, one after the other.
 * ADRS is not modified.
 */
static void fors_node_lanes(const Context *ctx, uint8_t *node, uint32_t i, unsigned z,
                            const ADRS *adrs)
{
    ADRS lane_adrs[MAX_LANES];
    uint8_t children[2 * MAX_LANES * N_MAX];    /* lnode || rnode of each subtree */
    uint8_t *lane_node[MAX_LANES];
    const uint8_t *M[MAX_LANES];
    unsigned j, n, lanes;

    n = ctx->n;
    lanes = LANES(ctx);
    assert(ctx->lanes == lanes);
    for (j = 0; j < lanes; j++)
        lane_node[j] = node + j*n;

    if (z == 0) {                                                       /*  1 */
        /* 2: sk = fors_skGen(SK.seed, PK.seed, ADRS, i), see Algorithm 14 */
        for (j = 0; j < lanes; j++) {
            lane_adrs[j] = *adrs;
            set_type_and_clear(&lane_adrs[j], FORS_PRF);
            set_key_pair_address(&lane_adrs[j], get_key_pair_address(adrs));
            set_tree_index(&lane_adrs[j], i + j);
        }
        thash_PRF_lanes(ctx, lane_node, lane_adrs);

        for (j = 0; j < lanes; j++) {
            lane_adrs[j] = *adrs;
            set_tree_height(&lane_adrs[j], 0);                          /*  3 */
            set_tree_index(&lane_adrs[j], i + j);                       /*  4 */
            M[j] = lane_node[j];
        }
        thash_F_lanes(ctx, lane_node, lane_adrs, M);                    /*  5 */
        return;
    }

    /* 7 and 8: the 2 * lanes children, lanes at a time */
    fors_node_lanes(ctx, children, 2*i, z - 1, adrs);
    fors_node_lanes(ctx, children + lanes*n, 2*i + lanes, z - 1, adrs);
    for (j = 0; j < lanes; j++) {
        lane_adrs[j] = *adrs;
        set_tree_height(&lane_adrs[j], z);                              /*  9 */
        set_tree_index(&lane_adrs[j], i + j);                           /* 10 */
        M[j] = children + 2*j*n;
    }
    thash_H_lanes(ctx, lane_node, lane_adrs, M);                        /* 11 */
}

#endif /* SLHDSA_LANES */

/*
 * fors_node (Algorithm 15): the root node of the FORS subtree of height z
 * whose leftmost leaf is i * 2^z, for the key pair in ADRS (of type FORS_TREE).
 */
static void fors_node(const Context *ctx, uint8_t *node, uint32_t i, unsigned z,
                      ADRS *adrs)
{
    uint8_t lnode_rnode[2 * N_MAX];
    uint8_t *lnode = lnode_rnode;
    uint8_t *rnode = lnode_rnode + ctx->n;
    uint8_t *sk = node;

    if (z == 0) {                                           /*  1 */
        fors_skgen(ctx, sk, adrs, i);                       /*  2 */
        set_tree_height(adrs, 0);                           /*  3 */
        set_tree_index(adrs, i);                            /*  4 */
        thash_F(ctx, node, adrs, sk);                       /*  5 */
        return;
    }

#ifdef SLHDSA_LANES
    if (ctx->lanes > 1 && z >= ctx->lg_lanes) {
        /*
         * Lines 7 and 8: the lanes descendants of height z - lg_lanes at once,
         * then the levels above them, up to lnode and rnode (height z - 1)
         */
        uint8_t nodes[MAX_LANES * N_MAX];
        unsigned count, height, j;

        height = z - ctx->lg_lanes;
        fors_node_lanes(ctx, nodes, i << ctx->lg_lanes, height, adrs);
        for (count = ctx->lanes / 2; count >= 2; count /= 2) {
            height++;
            for (j = 0; j < count; j++)
                fors_parent(ctx, nodes + j*ctx->n, (i << (z - height)) + j, height,
                            nodes + 2*j*ctx->n, adrs);
        }
        memcpy(lnode_rnode, nodes, 2 * ctx->n);
    } else
#endif
    {
        fors_node(ctx, lnode, 2*i, z - 1, adrs);            /*  7 */
        fors_node(ctx, rnode, 2*i + 1, z - 1, adrs);        /*  8 */
    }
    set_tree_height(adrs, z);                               /*  9 */
    set_tree_index(adrs, i);                                /* 10 */
    thash_H(ctx, node, adrs, lnode_rnode);                  /* 11 */
}

/*
 * The exported functions
 */

/*
 * F, H, T_l or PRF, depending on the length of M:
 * n bytes for F and PRF (with M = SK.seed), 2n for H, l*n for T_l.
 * n is the length in bytes of out and pk_seed (16, 24 or 32).
 */
EXPORT_SYM int slhdsa_thash(unsigned family, size_t n, unsigned lg_w,
                            uint8_t *out,
                            const uint8_t *pk_seed,
                            const uint8_t adrs[ADRS_LEN],
                            const uint8_t *m, size_t m_len)
{
    Context ctx;
    ADRS address;
    int res;

    if (NULL == out || NULL == adrs || NULL == m)
        return ERR_NULL;

    res = context_init(&ctx, family, n, lg_w, pk_seed, NULL);
    if (res)
        return res;

    if (m_len == 0 || m_len % n != 0 || m_len > LEN_MAX * N_MAX) {
        context_free(&ctx);
        return ERR_VALUE;
    }

    memcpy(address.bytes, adrs, ADRS_LEN);
    if (m_len == n)
        thash_F(&ctx, out, &address, m);
    else
        thash_T_l(&ctx, out, &address, m, m_len / n); /* H is T_2 */
    context_free(&ctx);
    return 0;
}

/*
 * chain (Algorithm 5): F iterated s times on x, from step i
 * (i + s must not be larger than w - 1).
 * n is the length in bytes of out, pk_seed and x (16, 24 or 32).
 * adrs is not modified.
 */
EXPORT_SYM int slhdsa_chain(unsigned family, size_t n, unsigned lg_w,
                            uint8_t *out,
                            const uint8_t *pk_seed,
                            const uint8_t adrs[ADRS_LEN],
                            const uint8_t *x,
                            unsigned i, unsigned s)
{
    Context ctx;
    ADRS address;
    int res;

    if (NULL == out || NULL == adrs || NULL == x)
        return ERR_NULL;

    res = context_init(&ctx, family, n, lg_w, pk_seed, NULL);
    if (res)
        return res;

    if (i > ctx.w - 1 || s > ctx.w - 1 - i) {
        context_free(&ctx);
        return ERR_VALUE;
    }

    memcpy(address.bytes, adrs, ADRS_LEN);
    chain(&ctx, out, x, i, s, &address);
    context_free(&ctx);
    return 0;
}

/*
 * The len WOTS+ chains of the key pair in adrs (of type WOTS_HASH), into out
 * (len*n bytes): chain i is chain(X_i, start[i], steps[i]) with chain address i,
 * where X_i is x[i] (x has len*n bytes), or the private value of the chain
 * if x is NULL (sk_seed is then needed). These are lines 8 to 16 of wots_sign
 * (Algorithm 7, with x NULL) and lines 8 to 11 of wots_pkFromSig (Algorithm 8).
 * n is the length in bytes of sk_seed and pk_seed (16, 24 or 32).
 * adrs is not modified.
 */
EXPORT_SYM int slhdsa_wots_chains(unsigned family, size_t n, unsigned lg_w,
                                  uint8_t *out,
                                  const uint8_t *sk_seed,
                                  const uint8_t *pk_seed,
                                  const uint8_t adrs[ADRS_LEN],
                                  const uint8_t *x,
                                  const uint8_t *start, const uint8_t *steps, size_t len)
{
    Context ctx;
    ADRS address;
    size_t i;
    int res;

    if (NULL == out || NULL == adrs || NULL == start || NULL == steps)
        return ERR_NULL;
    if (NULL == x && NULL == sk_seed)
        return ERR_NULL;

    res = context_init(&ctx, family, n, lg_w, pk_seed, sk_seed);
    if (res)
        return res;

    if (len != ctx.len)
        res = ERR_VALUE;
    for (i = 0; res == 0 && i < len; i++) {
        if (start[i] + steps[i] > ctx.w - 1)
            res = ERR_VALUE;
    }
    if (res == 0) {
        memcpy(address.bytes, adrs, ADRS_LEN);
        wots_chains(&ctx, out, x, start, steps, &address);
    }
    context_free(&ctx);
    return res;
}

/*
 * xmss_node (Algorithm 9): the root of the XMSS subtree of height z
 * whose leftmost leaf is i * 2^z, in the XMSS tree selected by adrs
 * (layer and tree address).
 * n is the length in bytes of out, sk_seed and pk_seed (16, 24 or 32).
 * adrs is not modified.
 */
EXPORT_SYM int slhdsa_xmss_node(unsigned family, size_t n, unsigned lg_w,
                                uint8_t *out,
                                const uint8_t *sk_seed,
                                const uint8_t *pk_seed,
                                const uint8_t adrs[ADRS_LEN],
                                uint32_t i, unsigned z)
{
    Context ctx;
    ADRS address;
    int res;

    if (NULL == out || NULL == sk_seed || NULL == adrs)
        return ERR_NULL;

    if (z > MAX_XMSS_HEIGHT || i >= (1UL << (MAX_XMSS_HEIGHT - z)))
        return ERR_VALUE;

    res = context_init(&ctx, family, n, lg_w, pk_seed, sk_seed);
    if (res)
        return res;

    memcpy(address.bytes, adrs, ADRS_LEN);
    xmss_node(&ctx, out, i, z, &address);
    context_free(&ctx);
    return 0;
}

/*
 * fors_node (Algorithm 15): the root of the FORS subtree of height z
 * whose leftmost leaf is i * 2^z, for the FORS key pair in adrs
 * (of type FORS_TREE). The k FORS trees are side by side, so i can be
 * up to k * 2^(a - z) - 1.
 * n is the length in bytes of out, sk_seed and pk_seed (16, 24 or 32).
 * adrs is not modified.
 */
EXPORT_SYM int slhdsa_fors_node(unsigned family, size_t n, unsigned lg_w,
                                uint8_t *out,
                                const uint8_t *sk_seed,
                                const uint8_t *pk_seed,
                                const uint8_t adrs[ADRS_LEN],
                                uint32_t i, unsigned z)
{
    Context ctx;
    ADRS address;
    int res;

    if (NULL == out || NULL == sk_seed || NULL == adrs)
        return ERR_NULL;

    if (z > MAX_FORS_HEIGHT || i >= (MAX_FORS_LEAVES >> z))
        return ERR_VALUE;

    res = context_init(&ctx, family, n, lg_w, pk_seed, sk_seed);
    if (res)
        return res;

    memcpy(address.bytes, adrs, ADRS_LEN);
    fors_node(&ctx, out, i, z, &address);
    context_free(&ctx);
    return 0;
}
