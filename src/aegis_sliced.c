/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The AEGIS state of aegis_portable.c without NEON or SSE2, kept bitsliced
 * in 64-bit words. This file is not a module: it is included by aegis_portable.c,
 * after the S-box, bit_stage() and mix_xtime().
 */

/* An AES block, as 16 bytes in memory order */
typedef struct {
    uint64_t w[2];
} aes_block;

static inline aes_block blk_load(const uint8_t p[16])
{
    aes_block r;
    memcpy(r.w, p, 16);
    return r;
}

static inline void blk_store(uint8_t p[16], aes_block x)
{
    memcpy(p, x.w, 16);
}

static inline aes_block blk_xor(aes_block a, aes_block b)
{
    a.w[0] ^= b.w[0];
    a.w[1] ^= b.w[1];
    return a;
}

/*
 * The bitsliced form of 8 blocks, in which bit b of each byte (lane b) is block b.
 * Each 32-bit half holds bit k of the bytes of one AES row, in which byte c is
 * the AES column c: w[k] holds rows 0 and 2, w[8 + k] holds rows 1 and 3.
 */
typedef struct {
    word w[16];
} sliced;

#define NW      16
#define LANE0   0x0101010101010101ULL
#define LANE04  0x1111111111111111ULL

static inline void swapmove32(uint32_t *a, uint32_t *b, uint32_t mask, unsigned n)
{
    uint32_t t = (*b ^ (*a >> n)) & mask;

    *b ^= t;
    *a ^= t << n;
}

/* Transpose the 4x4 bytes of a block: w[j] (column j) <-> w[r] (row r) */
static void byte_stage(uint32_t w[4])
{
    swapmove32(&w[0], &w[1], 0x00FF00FF, 8);
    swapmove32(&w[2], &w[3], 0x00FF00FF, 8);
    swapmove32(&w[0], &w[2], 0x0000FFFF, 16);
    swapmove32(&w[1], &w[3], 0x0000FFFF, 16);
}

/* Convert the blocks at blk[b] into lane b (a NULL pointer is a zero block) */
static void bs_pack(sliced *x, const uint8_t *const blk[8])
{
    uint32_t w[4];
    unsigned b, j;

    for (b = 0; b < 8; b++) {
        UNROLL
        for (j = 0; j < 4; j++)
            w[j] = blk[b] ? LOAD_U32_LITTLE(blk[b] + 4*j) : 0;
        byte_stage(w);
        x->w[b] = w[0] | (uint64_t)w[2] << 32;
        x->w[8 + b] = w[1] | (uint64_t)w[3] << 32;
    }
    bit_stage(x->w);
    bit_stage(x->w + 8);
}

/* Convert lane b into the block at out[b] (skipped if NULL); x is overwritten */
static void bs_unpack(uint8_t *const out[8], sliced *x)
{
    uint32_t w[4];
    unsigned b, j;

    bit_stage(x->w);
    bit_stage(x->w + 8);
    for (b = 0; b < 8; b++) {
        if (NULL == out[b])
            continue;
        w[0] = (uint32_t)x->w[b];
        w[2] = (uint32_t)(x->w[b] >> 32);
        w[1] = (uint32_t)x->w[8 + b];
        w[3] = (uint32_t)(x->w[8 + b] >> 32);
        byte_stage(w);
        UNROLL
        for (j = 0; j < 4; j++)
            STORE_U32_LITTLE(out[b] + 4*j, w[j]);
    }
}

#define SWAP_HALVES(x)  (((x) << 32) | ((x) >> 32))

static inline uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

/*
 * The next row of the rows 0 and 2 (in p) is in q, that of the rows 1 and 3
 * is in p with the halves swapped.
 */
HOT void bs_round(sliced *x)
{
    word d0[8], d1[8];
    word *p = x->w, *q = x->w + 8;
    unsigned k;

    bitslice_Sbox(p);
    bitslice_Sbox(q);
    UNROLL
    for (k = 0; k < 8; k++) {
        /* Rows 0 (by 0) and 2 (by 16), rows 1 (by 8) and 3 (by 24) */
        p[k] = (uint32_t)p[k] | (uint64_t)rotr32((uint32_t)(p[k] >> 32), 16) << 32;
        q[k] = rotr32((uint32_t)q[k], 8) | (uint64_t)rotr32((uint32_t)(q[k] >> 32), 24) << 32;
        d0[k] = p[k] ^ q[k];
        d1[k] = q[k] ^ SWAP_HALVES(p[k]);
    }
    UNROLL
    for (k = 0; k < 8; k++) {
        word s0 = d1[k] ^ SWAP_HALVES(q[k]);
        word s1 = SWAP_HALVES(d0[k]) ^ p[k];

        p[k] = s0;
        q[k] = s1;
    }
    mix_xtime(p, d0);
    mix_xtime(q, d1);
}

/* The AEGIS state */
typedef sliced aegis_core;

#define AEGIS_CORE

/*
 * Each byte rotated left by one lane, within lanes 0-7 (AEGIS-128L) or 0-5
 * (the other lanes get unspecified values), or right by one lane
 */
#define ROT8(w)     ((((w) & 0x7F7F7F7F7F7F7F7FULL) << 1) | (((w) & 0x8080808080808080ULL) >> 7))
#define ROT6(w)     ((((w) & 0x1F1F1F1F1F1F1F1FULL) << 1) | (((w) & 0x2020202020202020ULL) >> 5))
#define ROTR8(w)    ((((w) >> 1) & 0x7F7F7F7F7F7F7F7FULL) | (((w) & 0x0101010101010101ULL) << 7))

/*
 * Update (3.3 and 4.3): S'[i] = AESRound(S[i-1], S[i]), with the message blocks
 * in lanes 0 and 4 (AEGIS-128L) or in lane 0 (AEGIS-256) of m.
 * The blocks are rotated (S[i-1] to lane i) before the round, which is the same
 * as after it (Section 4.1). For AEGIS-256 (lanes 0 to 5), lanes 6 and 7 then hold
 * values that are never used: the rotation, the keystream and the tag ignore them.
 */
HOT void bs_update(aegis_core *c, unsigned variant, const sliced *m, sliced *t)
{
    unsigned k;

    if (variant == AEGIS_128L) {
        UNROLL
        for (k = 0; k < NW; k++) {
            t->w[k] = ROT8(c->w[k]);
            c->w[k] ^= m->w[k] & LANE04;
        }
        bs_round(t);
        UNROLL
        for (k = 0; k < NW; k++)
            c->w[k] ^= t->w[k];
    } else {
        UNROLL
        for (k = 0; k < NW; k++) {
            t->w[k] = ROT6(c->w[k]);
            c->w[k] ^= m->w[k] & LANE0;
        }
        bs_round(t);
        UNROLL
        for (k = 0; k < NW; k++)
            c->w[k] ^= t->w[k];
    }
}

/* The keystream of 3.6 (z0 in lane 0, z1 in lane 4) or of 4.6 (z in lane 0) */
static inline word ks_128l(word w)
{
    /* Lane 0: S1 ^ (S2 & S3) ^ S6; lane 4: S5 ^ (S6 & S7) ^ S2 */
    return (((w >> 1) ^ ((w >> 2) & (w >> 3))) & LANE04)
         ^ ((w >> 6) & LANE0) ^ ((w << 2) & (LANE0 << 4));
}

static inline word ks_256(word w)
{
    /* S1 ^ S4 ^ S5 ^ (S2 & S3) */
    return ((w >> 1) ^ (w >> 4) ^ (w >> 5) ^ ((w >> 2) & (w >> 3))) & LANE0;
}

HOT void bs_keystream(sliced *z, const aegis_core *c, unsigned variant)
{
    unsigned k;

    if (variant == AEGIS_128L) {
        UNROLL
        for (k = 0; k < NW; k++)
            z->w[k] = ks_128l(c->w[k]);
    } else {
        UNROLL
        for (k = 0; k < NW; k++)
            z->w[k] = ks_256(c->w[k]);
    }
}

static void core_load(aegis_core *c, unsigned variant, const aes_block S[8])
{
    uint8_t b[128];
    const uint8_t *blk[8];
    unsigned i;

    for (i = 0; i < 8; i++) {
        blk_store(b + 16*i, S[i]);
        blk[i] = (variant == AEGIS_256 && i >= 6) ? NULL : b + 16*i;
    }
    bs_pack(c, blk);
    wipe(b, sizeof b);
}

static void core_store(aes_block S[8], const aegis_core *c, unsigned variant)
{
    uint8_t b[128];
    uint8_t *blk[8];
    sliced x = *c;
    unsigned i;

    (void)variant;
    for (i = 0; i < 8; i++)
        blk[i] = b + 16*i;
    bs_unpack(blk, &x);
    for (i = 0; i < 8; i++)
        S[i] = blk_load(b + 16*i);
    wipe(&x, sizeof x);
    wipe(b, sizeof b);
}

static void core_absorb(aegis_core *c, unsigned variant, const uint8_t *p)
{
    const uint8_t *blk[8] = { NULL };
    sliced m, t;

    blk[0] = p;
    if (variant == AEGIS_128L)
        blk[4] = p + 16;
    bs_pack(&m, blk);
    bs_update(c, variant, &m, &t);
    wipe(&m, sizeof m);
    wipe(&t, sizeof t);
}

static void core_keystream(const aegis_core *c, unsigned variant, uint8_t *ks)
{
    uint8_t *blk[8] = { NULL };
    sliced z;

    blk[0] = ks;
    if (variant == AEGIS_128L)
        blk[4] = ks + 16;
    bs_keystream(&z, c, variant);
    bs_unpack(blk, &z);
    wipe(&z, sizeof z);
}

/*
 * Up to 128 bytes at a time (4 updates of AEGIS-128L, 8 of AEGIS-256): the input
 * blocks are converted together, and so is the keystream. The blocks of update u
 * are in lane u (and in lane 4 + u for the second block of AEGIS-128L).
 * When decrypting, the plaintext absorbed by the state is the converted ciphertext
 * XOR the keystream (the conversion is linear).
 */
static size_t core_crypt(aegis_core *c, unsigned variant,
                         const uint8_t *in, uint8_t *out, size_t len, int decrypt)
{
    unsigned bpu = variant == AEGIS_128L ? 2 : 1;       /* Blocks per update */
    uint64_t dmask = decrypt ? ~(uint64_t)0 : 0;
    sliced s, x, t, m;
    size_t done = 0;

    /* A local copy of the state, which the output pointer cannot alias */
    s = *c;
    while (len - done >= 16*bpu) {
        size_t left = (len - done) / (16*bpu);
        unsigned n = left >= 8/bpu ? 8/bpu : (unsigned)left;   /* Updates */
        const uint8_t *src[8];
        uint8_t *dst[8];
        unsigned u, k, lane;

        /*
         * Update u takes lane u (and 4 + u for AEGIS-128L): the keystream
         * is added in lane 0 (and 4), then the lanes of x are rotated by one.
         * After n updates, the block of lane L is in lane L - n (mod 8).
         */
        for (lane = 0; lane < 8; lane++) {
            size_t pos;

            u = lane & (8/bpu - 1);
            pos = done + 16*(bpu*u + lane / (8/bpu));
            src[lane] = u < n ? in + pos : NULL;
            dst[(lane - n) & 7] = u < n && NULL != out ? out + pos : NULL;
        }
        bs_pack(&x, src);
        for (u = 0; u < n; u++) {
            bs_keystream(&t, &s, variant);
            UNROLL
            for (k = 0; k < NW; k++) {
                m.w[k] = x.w[k] ^ (t.w[k] & dmask);     /* The plaintext */
                x.w[k] = ROTR8(x.w[k] ^ t.w[k]);
            }
            bs_update(&s, variant, &m, &t);
        }
        bs_unpack(dst, &x);
        done += 16*bpu*n;
    }
    *c = s;

    wipe(&s, sizeof s);
    wipe(&x, sizeof x);
    wipe(&t, sizeof t);
    wipe(&m, sizeof m);
    return done;
}

