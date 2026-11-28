/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The memory-hard part of Argon2 (RFC 9106, version 0x13): the memory
 * of 1 KiB blocks and how they are filled, one segment at a time.
 *
 * The rest (H0, the first two blocks of each lane, and the final tag,
 * all with BLAKE2b) is computed in Python, and so is the order of the
 * segments: all the lanes of a slice can be filled at the same time,
 * by different threads, and the slices of each pass follow each other.
 *
 * The indexing follows the reference implementation (phc-winner-argon2),
 * which RFC 9106 describes.
 *
 * Inside the memory, every block is kept as 128 words in native
 * endianess: blocks are converted only when they come in or go out.
 */

#include "common.h"
#include "endianess.h"

#if defined(__linux__)
#include <sys/mman.h>
#endif

/*
 * - if ARGON2_MODULE is defined, the functions are exported from the
 *   Python extension module with that name (default: argon2_core)
 * - if ARGON2_AVX2 is defined, the blocks are computed with AVX2
 *   (see argon2_avx2_bmi2.c)
 */
#ifndef ARGON2_MODULE
#define ARGON2_MODULE argon2_core
#endif

FAKE_INIT(ARGON2_MODULE)

#define BLOCK_WORDS     128
#define BLOCK_SIZE      (BLOCK_WORDS*8)
#define SYNC_POINTS     4       /* The slices of a pass */

/* The types of Argon2 (y) */
#define ARGON2_D        0
#define ARGON2_I        1
#define ARGON2_ID       2

typedef struct {
    uint64_t v[BLOCK_WORDS];
} block;

typedef struct {
    block *memory;          /* lanes * lane_length blocks */
    size_t size;            /* the size of the memory, in bytes */
    uint32_t blocks;        /* m', the number of blocks */
    uint32_t lanes;         /* p */
    uint32_t lane_length;   /* q = m' / p */
    uint32_t segment_length;
    uint32_t passes;        /* t */
    uint32_t type;          /* y */
} argon2_state;

/**
 * Set @len bytes to zero, in a way that the compiler cannot remove
 * (the memory is derived from the password, and it is about to be freed).
 * The call through a volatile pointer keeps the speed of memset(),
 * which matters for gigabytes.
 */
static void *(*const volatile memset_v)(void*, int, size_t) = memset;

static void wipe(void *p, size_t len)
{
    (void)memset_v(p, 0, len);
}

/**
 * Allocate the memory for the blocks (@size bytes).
 *
 * On Linux, a large area is aligned to 2 MiB and marked for transparent
 * huge pages, as in scrypt: it takes much fewer page faults and TLB misses.
 * Free it with align_free().
 */
static void *alloc_memory(size_t size)
{
#if defined(__linux__) && defined(MADV_HUGEPAGE)
    const size_t huge_page = 2U*1024*1024;
    void *m;

    if (size >= huge_page) {
        m = align_alloc(size, (unsigned)huge_page);
        if (m != NULL) {
            /* Only a hint: it is not an error if the kernel ignores it */
            (void)madvise(m, size, MADV_HUGEPAGE);
        }
        return m;
    }
#endif
    return align_alloc(size, 64);
}

/*
 * The compression function G (RFC 9106, Section 3.5):
 * @next = G(@prev, @ref), or, with @with_xor, @next ^= G(@prev, @ref).
 * @next may be the same block as @ref (for the addresses of Argon2i).
 *
 * G computes R = @prev ^ @ref, applies the permutation P (Figure 18)
 * to each of the 8 rows of R (16 consecutive words), then to each of
 * its 8 columns (8 pairs of words, 16 words apart), and XORs the result
 * with R.
 *
 * P is a round of BLAKE2b on a 4x4 matrix of words: GB on each column of
 * the matrix, then on each diagonal. The SIMD versions compute GB on several
 * columns at once; to do the same on the diagonals, they first rotate
 * the rows of the matrix (by 1, 2 and 3 words), and then rotate them back.
 *
 * There are 3 versions, which compute the same result:
 * - AVX2, with 4 words in each register: in argon2_avx2_bmi2.c (ARGON2_AVX2);
 * - SSE2 (with USE_SSE2, always on x86-64), with 2 words in each register;
 * - portable C, one word at a time.
 *
 * Speed of a 64 MiB pass, on an Intel i5-1240P with gcc 15 (2026-11):
 * AVX2 is 1.7 times as fast as portable C on a performance core,
 * and 1.4 times on an efficiency core. SSE2 is as fast as portable C on
 * a performance core (9% faster with clang), 1.2 times as fast on an efficiency
 * core, and 2.3 times as fast on 32-bit x86, where C has no 64-bit registers.
 *
 * There is no NEON version: on a Cortex-A53 (Raspberry Pi 3), the same
 * code as SSE2 with NEON is 12% slower than portable C with gcc 14,
 * and only 5% faster with clang 19.
 */

#if defined(ARGON2_AVX2) || defined(USE_SSE2)

/* GB of RFC 9106 (Figure 19), on all the words of the registers a, b, c, d */
#define GB_SIMD(a, b, c, d) do {    \
        a = blamka(a, b);           \
        d = ROTR32(XOR(d, a));      \
        c = blamka(c, d);           \
        b = ROTR24(XOR(b, c));      \
        a = blamka(a, b);           \
        d = ROTR16(XOR(d, a));      \
        c = blamka(c, d);           \
        b = ROTR63(XOR(b, c));      \
    } while (0)

/*
 * P on 4x4 matrices whose rows are in a0+a1, b0+b1, c0+c1 and d0+d1,
 * with the macros ROTATE_ROW_1/2/3, which rotate a row by 1, 2 or 3 words.
 * Both are also used by argon2_avx2_bmi2.c.
 */
#define P_SIMD(a0, a1, b0, b1, c0, c1, d0, d1) do {                     \
        GB_SIMD(a0, b0, c0, d0);                                        \
        GB_SIMD(a1, b1, c1, d1);                                        \
        ROTATE_ROW_1(b0, b1); ROTATE_ROW_2(c0, c1); ROTATE_ROW_3(d0, d1); \
        GB_SIMD(a0, b0, c0, d0);                                        \
        GB_SIMD(a1, b1, c1, d1);                                        \
        ROTATE_ROW_3(b0, b1); ROTATE_ROW_2(c0, c1); ROTATE_ROW_1(d0, d1); \
    } while (0)

#endif

#if defined(ARGON2_AVX2)

/* Defined in argon2_avx2_bmi2.c, which includes this file first */
static void fill_block(const block *prev, const block *ref, block *next, int with_xor);

#elif defined(USE_SSE2)

#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif

/* a + b + 2 * trunc(a) * trunc(b), on each word */
static inline __m128i blamka(__m128i a, __m128i b)
{
    __m128i p = _mm_mul_epu32(a, b);
    return _mm_add_epi64(_mm_add_epi64(a, b), _mm_add_epi64(p, p));
}

#define XOR(a, b)   _mm_xor_si128(a, b)
#define ROTR32(x)   _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1))
#define ROTR24(x)   _mm_xor_si128(_mm_srli_epi64(x, 24), _mm_slli_epi64(x, 40))
#define ROTR16(x)   _mm_shufflehi_epi16(_mm_shufflelo_epi16(x, _MM_SHUFFLE(0, 3, 2, 1)), _MM_SHUFFLE(0, 3, 2, 1))
#define ROTR63(x)   _mm_xor_si128(_mm_srli_epi64(x, 63), _mm_add_epi64(x, x))

/*
 * A row (x[0..3]) of a matrix is split across two registers: x[0..1] in x0,
 * and x[2..3] in x1. Rotated by one word, it is (x[1] x[2], x[3] x[0]):
 * the middle words of (x0, x1), and of (x1, x0).
 */
#define MIDDLE(x, y)    _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x), _mm_castsi128_pd(y), 1))

#define ROTATE_ROW_1(x0, x1) do { __m128i t = MIDDLE(x0, x1); x1 = MIDDLE(x1, x0); x0 = t; } while (0)
#define ROTATE_ROW_2(x0, x1) do { __m128i t = x0; x0 = x1; x1 = t; } while (0)
#define ROTATE_ROW_3(x0, x1) do { __m128i t = MIDDLE(x1, x0); x1 = MIDDLE(x0, x1); x0 = t; } while (0)

static void fill_block(const block *prev, const block *ref, block *next, int with_xor)
{
    __m128i r[64], tmp[64];
    unsigned i;

    for (i=0; i<64; i++) {
        r[i] = XOR(_mm_loadu_si128((const __m128i*)&prev->v[2*i]),
                   _mm_loadu_si128((const __m128i*)&ref->v[2*i]));
        tmp[i] = r[i];
        if (with_xor) {
            tmp[i] = XOR(tmp[i], _mm_loadu_si128((const __m128i*)&next->v[2*i]));
        }
    }

    /* Row i: registers 8i..8i+7 */
    for (i=0; i<8; i++) {
        P_SIMD(r[8*i+0], r[8*i+1], r[8*i+2], r[8*i+3],
               r[8*i+4], r[8*i+5], r[8*i+6], r[8*i+7]);
    }

    /* Column i (words 2i and 2i+1 of each row): registers i, i+8, ..., i+56 */
    for (i=0; i<8; i++) {
        P_SIMD(r[i+0],  r[i+8],  r[i+16], r[i+24],
               r[i+32], r[i+40], r[i+48], r[i+56]);
    }

    for (i=0; i<64; i++) {
        _mm_storeu_si128((__m128i*)&next->v[2*i], XOR(tmp[i], r[i]));
    }
}

#else /* portable C */

static inline uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

/* The BlaMka addition: a + b + 2 * trunc(a) * trunc(b) */
static inline uint64_t blamka(uint64_t a, uint64_t b)
{
    return a + b + 2 * ((a & 0xFFFFFFFFU) * (b & 0xFFFFFFFFU));
}

/* GB of RFC 9106 (Figure 19) */
#define GB(a, b, c, d) do {         \
        a = blamka(a, b);           \
        d = rotr64(d ^ a, 32);      \
        c = blamka(c, d);           \
        b = rotr64(b ^ c, 24);      \
        a = blamka(a, b);           \
        d = rotr64(d ^ a, 16);      \
        c = blamka(c, d);           \
        b = rotr64(b ^ c, 63);      \
    } while (0)

/*
 * The permutation P (RFC 9106, Figure 18) on the 16 words
 * v[i0], v[i0+s], ... , v[i0+15*s] (with s=1 for the rows, where the
 * 16 words are consecutive). The column version takes pairs of words,
 * so it is written with the index of each word.
 */
#define P(v, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) do { \
        GB(v[i0], v[i4], v[i8],  v[i12]);   \
        GB(v[i1], v[i5], v[i9],  v[i13]);   \
        GB(v[i2], v[i6], v[i10], v[i14]);   \
        GB(v[i3], v[i7], v[i11], v[i15]);   \
        GB(v[i0], v[i5], v[i10], v[i15]);   \
        GB(v[i1], v[i6], v[i11], v[i12]);   \
        GB(v[i2], v[i7], v[i8],  v[i13]);   \
        GB(v[i3], v[i4], v[i9],  v[i14]);   \
    } while (0)

static void fill_block(const block *prev, const block *ref, block *next, int with_xor)
{
    block r, tmp;
    unsigned i;

    for (i=0; i<BLOCK_WORDS; i++) {
        r.v[i] = prev->v[i] ^ ref->v[i];
    }
    tmp = r;
    if (with_xor) {
        for (i=0; i<BLOCK_WORDS; i++) {
            tmp.v[i] ^= next->v[i];
        }
    }

    /* P on each row: 16 consecutive words */
    for (i=0; i<8; i++) {
        uint64_t *v = &r.v[16*i];
        P(v, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    }

    /* P on each column: 8 pairs of words, 16 words apart */
    for (i=0; i<8; i++) {
        uint64_t *v = &r.v[2*i];
        P(v, 0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113);
    }

    for (i=0; i<BLOCK_WORDS; i++) {
        next->v[i] = tmp.v[i] ^ r.v[i];
    }
}

#endif /* ARGON2_AVX2, USE_SSE2, portable C */

/**
 * The next block of pseudo-random addresses, for the data-independent
 * addressing (RFC 9106, Section 3.4.1.2): G(0, G(0, input)), with the
 * counter in the input incremented first.
 */
static void next_addresses(block *addresses, block *input, const block *zero)
{
    input->v[6]++;
    fill_block(zero, input, addresses, 0);
    fill_block(zero, addresses, addresses, 0);
}

/**
 * The column in lane @ref_lane of the reference block of the block
 * @index of a segment (RFC 9106, Section 3.4.2), given the 32 bits J_1
 * of @pseudo_rand.
 */
static uint32_t index_alpha(const argon2_state *st, uint32_t pass, uint32_t slice,
                            uint32_t index, uint32_t j1, int same_lane)
{
    uint32_t area_size, start;
    uint64_t relative;

    if (pass == 0) {
        if (slice == 0) {
            /* All the previous blocks of the segment, but the last one */
            area_size = index - 1;
        } else if (same_lane) {
            area_size = slice * st->segment_length + index - 1;
        } else {
            area_size = slice * st->segment_length - (index == 0 ? 1 : 0);
        }
    } else {
        if (same_lane) {
            area_size = st->lane_length - st->segment_length + index - 1;
        } else {
            area_size = st->lane_length - st->segment_length - (index == 0 ? 1 : 0);
        }
    }

    /* Map J_1 to [0, area_size), with more weight to the most recent blocks */
    relative = j1;
    relative = (relative * relative) >> 32;
    relative = area_size - 1 - ((area_size * relative) >> 32);

    /* The area starts after the current slice, except in the first pass */
    start = 0;
    if (pass != 0 && slice != SYNC_POINTS - 1) {
        start = (slice + 1) * st->segment_length;
    }

    return (uint32_t)((start + relative) % st->lane_length);
}

/**
 * Create the memory for Argon2.
 *
 * @state:  the new state (to be freed with argon2_destroy())
 * @blocks: m', the number of 1 KiB blocks: a multiple of 4*@lanes,
 *          and at least 8*@lanes
 * @lanes:  p, from 1 to 2^24-1
 * @passes: t, at least 1
 * @type:   y (0 for Argon2d, 1 for Argon2i, 2 for Argon2id)
 *
 * The memory is not initialized: argon2_set_block() sets the first two
 * blocks of each lane, and argon2_fill_segment() computes all the others.
 */
EXPORT_SYM int argon2_new(argon2_state **state, uint32_t blocks, uint32_t lanes,
                          uint32_t passes, uint32_t type)
{
    argon2_state *st;
    size_t size;

    if (NULL == state) {
        return ERR_NULL;
    }
    *state = NULL;

    if (lanes == 0 || lanes >= (1U << 24) || passes == 0 || type > ARGON2_ID) {
        return ERR_VALUE;
    }
    if (blocks % (SYNC_POINTS * lanes) || blocks / lanes < 2 * SYNC_POINTS) {
        return ERR_VALUE;
    }

    /* Up to 4 TiB: it does not fit in the address space of 32-bit systems */
#if SIZE_MAX / BLOCK_SIZE < UINT32_MAX
    if (blocks > SIZE_MAX / BLOCK_SIZE) {
        return ERR_MEMORY;
    }
#endif
    size = (size_t)blocks * BLOCK_SIZE;

    st = (argon2_state*)calloc(1, sizeof(argon2_state));
    if (NULL == st) {
        return ERR_MEMORY;
    }
    st->memory = (block*)alloc_memory(size);
    if (NULL == st->memory) {
        free(st);
        return ERR_MEMORY;
    }

    st->size = size;
    st->blocks = blocks;
    st->lanes = lanes;
    st->lane_length = blocks / lanes;
    st->segment_length = st->lane_length / SYNC_POINTS;
    st->passes = passes;
    st->type = type;

    *state = st;
    return 0;
}

/**
 * Wipe the memory, and free it.
 */
EXPORT_SYM int argon2_destroy(argon2_state *st)
{
    if (NULL == st) {
        return ERR_NULL;
    }
    wipe(st->memory, st->size);
    align_free(st->memory);
    wipe(st, sizeof(argon2_state));
    free(st);
    return 0;
}

/**
 * Set the block in column @index of lane @lane to the 1024 bytes @in
 * (for B[i][0] and B[i][1], computed with H').
 */
EXPORT_SYM int argon2_set_block(argon2_state *st, uint32_t lane, uint32_t index, const uint8_t *in)
{
    block *b;
    unsigned i;

    if (NULL == st || NULL == in) {
        return ERR_NULL;
    }
    if (lane >= st->lanes || index >= st->lane_length) {
        return ERR_VALUE;
    }

    b = &st->memory[(size_t)lane * st->lane_length + index];
    for (i=0; i<BLOCK_WORDS; i++) {
        b->v[i] = LOAD_U64_LITTLE(&in[8*i]);
    }
    return 0;
}

/**
 * Fill the segment of lane @lane in slice @slice of pass @pass
 * (RFC 9106, Section 3.2, steps 5 and 6).
 *
 * The caller must fill the segments in order: all the segments of slice 0
 * of pass 0 (in any order of lanes), then those of slice 1, and so on.
 *
 * Several threads can call this function at the same time on the same
 * state, for different lanes of the same slice: a segment only reads
 * the blocks of other lanes in the slices already finished.
 */
EXPORT_SYM int argon2_fill_segment(argon2_state *st, uint32_t pass, uint32_t slice, uint32_t lane)
{
    block addresses, input, zero;
    uint32_t i, start, curr, prev;
    int data_independent;

    if (NULL == st) {
        return ERR_NULL;
    }
    if (pass >= st->passes || slice >= SYNC_POINTS || lane >= st->lanes) {
        return ERR_VALUE;
    }

    data_independent = (st->type == ARGON2_I) ||
                       (st->type == ARGON2_ID && pass == 0 && slice < SYNC_POINTS / 2);

    if (data_independent) {
        memset(&zero, 0, sizeof zero);
        memset(&input, 0, sizeof input);
        input.v[0] = pass;
        input.v[1] = lane;
        input.v[2] = slice;
        input.v[3] = st->blocks;
        input.v[4] = st->passes;
        input.v[5] = st->type;
    }

    /* The first two blocks of each lane come from H' */
    start = 0;
    if (pass == 0 && slice == 0) {
        start = 2;
        if (data_independent) {
            next_addresses(&addresses, &input, &zero);
        }
    }

    /* The column of the current block, and of the previous one */
    curr = slice * st->segment_length + start;
    prev = (curr == 0) ? st->lane_length - 1 : curr - 1;

    for (i=start; i<st->segment_length; i++, curr++, prev = curr - 1) {
        block *lane_base = &st->memory[(size_t)lane * st->lane_length];
        const block *ref;
        uint64_t pseudo_rand;
        uint32_t ref_lane, ref_index;

        /* J_1 and J_2 (RFC 9106, Section 3.4.1) */
        if (data_independent) {
            if (i % BLOCK_WORDS == 0) {
                next_addresses(&addresses, &input, &zero);
            }
            pseudo_rand = addresses.v[i % BLOCK_WORDS];
        } else {
            pseudo_rand = lane_base[prev].v[0];
        }

        /* The lane of the reference block: the current one in the first slice */
        ref_lane = (uint32_t)((pseudo_rand >> 32) % st->lanes);
        if (pass == 0 && slice == 0) {
            ref_lane = lane;
        }

        ref_index = index_alpha(st, pass, slice, i, (uint32_t)pseudo_rand, ref_lane == lane);
        ref = &st->memory[(size_t)ref_lane * st->lane_length + ref_index];

        /* From the second pass, the new block is XORed with the old one */
        fill_block(&lane_base[prev], ref, &lane_base[curr], pass != 0);
    }

    wipe(&addresses, sizeof addresses);
    return 0;
}

/**
 * The final block C: the XOR of the last column (RFC 9106, Section 3.2,
 * step 7), as 1024 bytes in @out.
 */
EXPORT_SYM int argon2_get_final_block(const argon2_state *st, uint8_t *out)
{
    block c;
    uint32_t lane;
    unsigned i;

    if (NULL == st || NULL == out) {
        return ERR_NULL;
    }

    c = st->memory[st->lane_length - 1];
    for (lane=1; lane<st->lanes; lane++) {
        const block *b = &st->memory[(size_t)lane * st->lane_length + st->lane_length - 1];
        for (i=0; i<BLOCK_WORDS; i++) {
            c.v[i] ^= b->v[i];
        }
    }

    for (i=0; i<BLOCK_WORDS; i++) {
        STORE_U64_LITTLE(&out[8*i], c.v[i]);
    }
    wipe(&c, sizeof c);
    return 0;
}
