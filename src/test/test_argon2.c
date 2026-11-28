/*
 * Test of the memory-hard part of Argon2 (argon2.c), for each build of
 * the compression function G:
 * - argon2.c without SSE2 (portable C),
 * - argon2.c with SSE2 (USE_SSE2),
 * - argon2_avx2_bmi2.c (TEST_ARGON2_AVX2). On a CPU without AVX2 that test
 *   does nothing, unless ARGON2_REQUIRE_AVX2 is set.
 *
 * The test includes the module, to reach its internals (fill_block() and
 * the memory of the state), and it is linked with BLAKE2b (blake2b.c),
 * to compute complete tags as the Python code does (H0, H' and the final tag).
 *
 * Correctness:
 * - the tags of RFC 9106 (Section 5), for the 3 types;
 * - tags from libargon2, for shapes of memory that stress the indexing;
 * - fill_block() against a reference G written from RFC 9106.
 *
 * Memory safety, on top of ASan and UBSan (enabled for all the tests with gcc
 * and clang; LeakSanitizer finds a state that is not freed):
 * - fill_block() on blocks allocated separately with their exact size, so that
 *   ASan catches a load or store out of a block; on misaligned blocks; and with
 *   the output in place of the reference block (as for the addresses of Argon2i);
 * - argon2_fill_segment() only writes its own segment, and, with ASan, it does
 *   not read the blocks that it must not depend on: they are poisoned. These
 *   are the segments of the other lanes in the same slice (which other threads
 *   fill at the same time), and, in the first pass, the blocks not computed yet.
 *   The lanes of each slice are filled in a random order;
 * - the errors of all the functions, which must not touch the memory.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(TEST_ARGON2_AVX2)
#include "argon2_avx2_bmi2.c"
#else
#include "argon2.c"
#endif

/** ASan: poison the blocks that a segment must not read **/
#if defined(__SANITIZE_ADDRESS__)
#define HAVE_ASAN
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HAVE_ASAN
#endif
#endif

#if defined(HAVE_ASAN)
#include <sanitizer/asan_interface.h>
#define POISON(p, n)        ASAN_POISON_MEMORY_REGION(p, n)
#define UNPOISON(p, n)      ASAN_UNPOISON_MEMORY_REGION(p, n)
#define IS_POISONED(p)      __asan_address_is_poisoned(p)
#else
#define POISON(p, n)        ((void)(p), (void)(n))
#define UNPOISON(p, n)      ((void)(p), (void)(n))
#define IS_POISONED(p)      ((void)(p), 0)
#endif

/** BLAKE2b (blake2b.c) **/
typedef void blake2b_state;
int blake2b_init(blake2b_state **state, const uint8_t *key, size_t key_size, size_t digest_size);
int blake2b_destroy(blake2b_state *state);
int blake2b_update(blake2b_state *state, const uint8_t *in, size_t len);
int blake2b_digest(const blake2b_state *state, uint8_t digest[64]);

static int failures = 0;

#define CHECK(cond) do {                                            \
        if (!(cond)) {                                              \
            printf("Failed at line %d: %s\n", __LINE__, #cond);     \
            failures++;                                             \
        }                                                           \
    } while (0)

static void le32(uint8_t out[4], uint32_t x)
{
    out[0] = (uint8_t)x;
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
}

/** BLAKE2b of the concatenation of in1 and in2, with a digest of len bytes (1 to 64) **/
static void blake2b(uint8_t *out, size_t len, const uint8_t *in1, size_t len1, const uint8_t *in2, size_t len2)
{
    blake2b_state *hs;
    uint8_t digest[64];
    int result;

    result = blake2b_init(&hs, (const uint8_t*)"", 0, len);
    assert(result == 0);
    result = blake2b_update(hs, in1, len1);
    assert(result == 0);
    result = blake2b_update(hs, in2, len2);
    assert(result == 0);
    result = blake2b_digest(hs, digest);
    assert(result == 0);
    blake2b_destroy(hs);
    memcpy(out, digest, len);
}

/** The variable-length hash H' (RFC 9106, Section 3.3) **/
static void h_prime(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
    uint8_t prefix[4];
    uint8_t v[64];
    size_t r, i;

    le32(prefix, (uint32_t)out_len);
    if (out_len <= 64) {
        blake2b(out, out_len, prefix, 4, in, in_len);
        return;
    }
    r = (out_len + 31) / 32 - 2;
    blake2b(v, 64, prefix, 4, in, in_len);
    memcpy(out, v, 32);
    for (i=1; i<r; i++) {
        blake2b(v, 64, v, 64, NULL, 0);
        memcpy(out + 32*i, v, 32);
    }
    blake2b(out + 32*r, out_len - 32*r, v, 64, NULL, 0);
}

/** A small PRNG (xorshift64), for the random blocks and the order of the lanes **/
static uint64_t prng_state = 0x0123456789ABCDEFULL;

static uint64_t prng(void)
{
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 7;
    prng_state ^= prng_state << 17;
    return prng_state;
}

/*
 * The blocks that the segment (pass, slice, lane) must not read, with
 * ASan: the segments of the other lanes in the same slice, and in the first
 * pass, all the blocks of the slices after this one.
 */
static void poison_forbidden(argon2_state *st, uint32_t pass, uint32_t slice, uint32_t lane)
{
    uint32_t l, s;

    for (l=0; l<st->lanes; l++) {
        for (s=0; s<SYNC_POINTS; s++) {
            int forbidden = (s == slice && l != lane) || (pass == 0 && s > slice);

            if (forbidden) {
                block *first = &st->memory[(size_t)l * st->lane_length + (size_t)s * st->segment_length];
                POISON(first, (size_t)st->segment_length * BLOCK_SIZE);
            }
        }
    }
}

/*
 * Fill all the segments, slice after slice, with the lanes of each slice in
 * a random order. Before each segment, poison the blocks that it must not read,
 * and check afterwards that it only wrote its own blocks.
 */
static void fill_memory_checked(argon2_state *st)
{
    block *copy;
    uint32_t pass, slice, i, order[8];

    assert(st->lanes <= 8);
    copy = (block*)malloc(st->size);
    assert(copy != NULL);

    for (pass=0; pass<st->passes; pass++) {
        for (slice=0; slice<SYNC_POINTS; slice++) {
            for (i=0; i<st->lanes; i++) {
                order[i] = i;
            }
            for (i=st->lanes-1; i>0; i--) {
                uint32_t j = (uint32_t)(prng() % (i + 1)), t = order[i];

                order[i] = order[j];
                order[j] = t;
            }

            for (i=0; i<st->lanes; i++) {
                uint32_t lane = order[i];
                size_t first = (size_t)lane * st->lane_length + (size_t)slice * st->segment_length;
                size_t b;

                memcpy(copy, st->memory, st->size);
                poison_forbidden(st, pass, slice, lane);
                CHECK(argon2_fill_segment(st, pass, slice, lane) == 0);
                UNPOISON(st->memory, st->size);

                /* All the blocks outside the segment are unchanged */
                for (b=0; b<st->blocks; b++) {
                    if (b < first || b >= first + st->segment_length) {
                        CHECK(memcmp(&st->memory[b], &copy[b], BLOCK_SIZE) == 0);
                    }
                }
            }
        }
    }
    free(copy);
}

/*
 * The tag of Argon2, computed as in Python (_argon2.py),
 * with the C code for the memory.
 */
static void argon2_tag(uint8_t *tag, uint32_t tag_len, uint32_t type, uint32_t t, uint32_t m, uint32_t p,
                       const uint8_t *pwd, uint32_t pwd_len, const uint8_t *salt, uint32_t salt_len,
                       const uint8_t *secret, uint32_t secret_len, const uint8_t *ad, uint32_t ad_len)
{
    uint8_t h0_input[4*10 + 256], h0[64 + 8], first[BLOCK_SIZE], final[BLOCK_SIZE];
    const uint32_t params[6] = { p, tag_len, m, t, 0x13, type };
    const uint8_t *fields[4] = { pwd, salt, secret, ad };
    const uint32_t lens[4] = { pwd_len, salt_len, secret_len, ad_len };
    argon2_state *st;
    size_t pos = 0;
    uint32_t lane, index;
    unsigned i;

    for (i=0; i<6; i++, pos+=4) {
        le32(h0_input + pos, params[i]);
    }
    for (i=0; i<4; i++) {
        assert(pos + 4 + lens[i] <= sizeof h0_input);
        le32(h0_input + pos, lens[i]);
        pos += 4;
        if (lens[i] > 0) {
            memcpy(h0_input + pos, fields[i], lens[i]);
        }
        pos += lens[i];
    }
    blake2b(h0, 64, h0_input, pos, NULL, 0);

    CHECK(argon2_new(&st, 4 * p * (m / (4 * p)), p, t, type) == 0);
    for (lane=0; lane<p; lane++) {
        for (index=0; index<2; index++) {
            le32(h0 + 64, index);
            le32(h0 + 68, lane);
            h_prime(first, BLOCK_SIZE, h0, sizeof h0);
            CHECK(argon2_set_block(st, lane, index, first) == 0);
        }
    }
    fill_memory_checked(st);
    CHECK(argon2_get_final_block(st, final) == 0);
    CHECK(argon2_destroy(st) == 0);

    h_prime(tag, tag_len, final, BLOCK_SIZE);
}

static unsigned nibble(char c)
{
    return (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static void unhex(uint8_t *out, const char *hex)
{
    size_t i;

    for (i=0; hex[2*i] != 0; i++) {
        out[i] = (uint8_t)(nibble(hex[2*i]) << 4 | nibble(hex[2*i + 1]));
    }
}

/** RFC 9106, Section 5: all 3 types, with t=3, m=32, p=4, a secret and associated data **/
static void test_rfc9106(void)
{
    static const char *tags[3] = {
        "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",  /* Argon2d */
        "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",  /* Argon2i */
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",  /* Argon2id */
    };
    uint8_t pwd[32], salt[16], secret[8], ad[12], tag[32], expected[32];
    uint32_t type;

    memset(pwd, 1, sizeof pwd);
    memset(salt, 2, sizeof salt);
    memset(secret, 3, sizeof secret);
    memset(ad, 4, sizeof ad);
    for (type=0; type<3; type++) {
        argon2_tag(tag, 32, type, 3, 32, 4, pwd, 32, salt, 16, secret, 8, ad, 12);
        unhex(expected, tags[type]);
        CHECK(memcmp(tag, expected, 32) == 0);
    }
}

/*
 * Tags from libargon2 (argon2-cffi 25.1.0), for the password "password" and
 * the salt "somesalt", with:
 *   argon2.low_level.hash_secret_raw(b"password", b"somesalt", t, m, p, tag_len, type, version=19)
 */
static void test_libargon2(void)
{
    static const struct {
        uint32_t type, t, m, p, tag_len;
        const char *tag;
    } vectors[] = {
        /* The minimum memory */
        { 2, 1,    8, 1, 32, "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3" },
        /* Segments of 256 blocks: two blocks of addresses in each one */
        { 1, 2, 1024, 1, 32, "fc0a265b35c6b8ee7a421997137a7dff447cd550f04d4683d7140c906c3e21b4" },
        /* m rounded down to 36 */
        { 0, 2,   37, 3, 32, "68b8fd10a10ea80742b0ab118e16a8407c0213846b084e4bbf3a733a34fcb192" },
        /* 5 lanes of 20 blocks */
        { 2, 3,  100, 5, 32, "7a26f62a09ab7f32f9e1110d38ea1108527365dc64c5fdc4c9cb08c70f0e51db" },
        { 1, 1,   64, 2, 16, "e12c71fd4a94af47eb717b0e0c0e5e6b" },
        /* Argon2id: addresses in the first half of the first pass only */
        { 2, 2, 2048, 2, 64, "c3bd4d9c39f0f816c1ce06ce6a7f05b9a0df3142006afeaa69ac542d93e994bd"
                             "5602e10cd2596583cfba26eb1c252964a06b64430142ec8db6f830f00c105c65" },
        { 0, 1,  256, 1, 32, "a95f9b293c856e8af8e525fb6111590554e5980e036f6d8bcbd79f86ac80d238" },
    };
    unsigned i;

    for (i=0; i<sizeof vectors / sizeof vectors[0]; i++) {
        uint8_t tag[64], expected[64];

        argon2_tag(tag, vectors[i].tag_len, vectors[i].type, vectors[i].t, vectors[i].m, vectors[i].p,
                   (const uint8_t*)"password", 8, (const uint8_t*)"somesalt", 8, NULL, 0, NULL, 0);
        unhex(expected, vectors[i].tag);
        CHECK(memcmp(tag, expected, vectors[i].tag_len) == 0);
    }
}

/** Reference G (RFC 9106, Section 3.5), written independently of the module **/
static uint64_t ref_rotr(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t ref_blamka(uint64_t x, uint64_t y)
{
    uint64_t xl = x & 0xFFFFFFFFU, yl = y & 0xFFFFFFFFU;

    return x + y + 2 * xl * yl;
}

static void ref_gb(uint64_t *w[16], unsigned a, unsigned b, unsigned c, unsigned d)
{
    *w[a] = ref_blamka(*w[a], *w[b]);
    *w[d] = ref_rotr(*w[d] ^ *w[a], 32);
    *w[c] = ref_blamka(*w[c], *w[d]);
    *w[b] = ref_rotr(*w[b] ^ *w[c], 24);
    *w[a] = ref_blamka(*w[a], *w[b]);
    *w[d] = ref_rotr(*w[d] ^ *w[a], 16);
    *w[c] = ref_blamka(*w[c], *w[d]);
    *w[b] = ref_rotr(*w[b] ^ *w[c], 63);
}

/* The permutation P (Figure 18), on 16 words given by their address */
static void ref_p(uint64_t *w[16])
{
    ref_gb(w, 0, 4, 8, 12);
    ref_gb(w, 1, 5, 9, 13);
    ref_gb(w, 2, 6, 10, 14);
    ref_gb(w, 3, 7, 11, 15);
    ref_gb(w, 0, 5, 10, 15);
    ref_gb(w, 1, 6, 11, 12);
    ref_gb(w, 2, 7, 8, 13);
    ref_gb(w, 3, 4, 9, 14);
}

/* out = G(x, y) */
static void ref_g(uint64_t out[128], const uint64_t x[128], const uint64_t y[128])
{
    uint64_t r[128], q[128];
    uint64_t *w[16];
    unsigned i, j;

    for (i=0; i<128; i++) {
        r[i] = q[i] = x[i] ^ y[i];
    }
    /* Each row: the 16 words 16*i .. 16*i+15 */
    for (i=0; i<8; i++) {
        for (j=0; j<16; j++) {
            w[j] = &q[16*i + j];
        }
        ref_p(w);
    }
    /* Each column: the words 2*i and 2*i+1 of each row */
    for (i=0; i<8; i++) {
        for (j=0; j<8; j++) {
            w[2*j] = &q[16*j + 2*i];
            w[2*j + 1] = &q[16*j + 2*i + 1];
        }
        ref_p(w);
    }
    for (i=0; i<128; i++) {
        out[i] = q[i] ^ r[i];
    }
}

static void random_block(block *b)
{
    unsigned i;

    for (i=0; i<BLOCK_WORDS; i++) {
        b->v[i] = prng();
    }
}

/*
 * fill_block() against the reference G, with and without XOR, on blocks
 * in separate allocations of exactly one block (for ASan), misaligned,
 * and with the output in place of the reference block.
 */
static void test_fill_block(void)
{
    block *prev, *ref, *next, *old;
    block expected;
    uint8_t *buffer;
    unsigned trial, i;

    prev = (block*)malloc(sizeof(block));
    ref = (block*)malloc(sizeof(block));
    next = (block*)malloc(sizeof(block));
    old = (block*)malloc(sizeof(block));
    assert(prev != NULL && ref != NULL && next != NULL && old != NULL);

    for (trial=0; trial<20; trial++) {
        random_block(prev);
        random_block(ref);
        random_block(next);
        *old = *next;

        /* next = G(prev, ref) */
        ref_g(expected.v, prev->v, ref->v);
        fill_block(prev, ref, next, 0);
        CHECK(memcmp(next, &expected, sizeof(block)) == 0);

        /* next ^= G(prev, ref) */
        *next = *old;
        fill_block(prev, ref, next, 1);
        for (i=0; i<BLOCK_WORDS; i++) {
            expected.v[i] ^= old->v[i];
        }
        CHECK(memcmp(next, &expected, sizeof(block)) == 0);

        /* In place: ref = G(prev, ref) */
        ref_g(expected.v, prev->v, ref->v);
        fill_block(prev, ref, ref, 0);
        CHECK(memcmp(ref, &expected, sizeof(block)) == 0);
    }

    /* Blocks aligned to 8 bytes only (the SIMD loads and stores are unaligned) */
    buffer = (uint8_t*)malloc(3 * sizeof(block) + 8);
    assert(buffer != NULL);
    {
        block *p = (block*)(buffer + 8);
        block *r = (block*)(buffer + 8 + sizeof(block));
        block *n = (block*)(buffer + 8 + 2 * sizeof(block));

        random_block(p);
        random_block(r);
        ref_g(expected.v, p->v, r->v);
        fill_block(p, r, n, 0);
        CHECK(memcmp(n, &expected, sizeof(block)) == 0);
    }

    free(buffer);
    free(prev);
    free(ref);
    free(next);
    free(old);
}

/** The errors of all the functions: they must not touch the memory **/
static void test_errors(void)
{
    argon2_state *st = NULL;
    uint8_t in[BLOCK_SIZE], out[BLOCK_SIZE];
    block *copy;
    uint32_t i;

    memset(in, 0xA5, sizeof in);

    /* argon2_new() */
    CHECK(argon2_new(NULL, 32, 1, 1, ARGON2_ID) == ERR_NULL);
    CHECK(argon2_new(&st, 32, 0, 1, ARGON2_ID) == ERR_VALUE);               /* no lanes */
    CHECK(argon2_new(&st, 1U << 26, 1U << 24, 1, ARGON2_ID) == ERR_VALUE);  /* too many lanes */
    CHECK(argon2_new(&st, 32, 1, 0, ARGON2_ID) == ERR_VALUE);               /* no passes */
    CHECK(argon2_new(&st, 32, 1, 1, 3) == ERR_VALUE);                       /* no such type */
    CHECK(argon2_new(&st, 34, 1, 1, ARGON2_ID) == ERR_VALUE);               /* not a multiple of 4 lanes */
    CHECK(argon2_new(&st, 12, 3, 1, ARGON2_ID) == ERR_VALUE);               /* less than 8 per lane */
    CHECK(argon2_new(&st, 4, 1, 1, ARGON2_ID) == ERR_VALUE);
    CHECK(argon2_new(&st, 0, 1, 1, ARGON2_ID) == ERR_VALUE);
    CHECK(st == NULL);
    if (sizeof(size_t) == 4) {
        /* 4 TiB do not fit in a 32-bit address space: no allocation is tried */
        CHECK(argon2_new(&st, 0xFFFFFFFCU, 1, 1, ARGON2_ID) == ERR_MEMORY);
        CHECK(st == NULL);
    }

    /* The smallest memory: 8 blocks for each lane */
    CHECK(argon2_new(&st, 24, 3, 2, ARGON2_ID) == 0);
    assert(st != NULL);
    CHECK(st->lane_length == 8 && st->segment_length == 2);
    for (i=0; i<3; i++) {
        CHECK(argon2_set_block(st, i, 0, in) == 0);
        CHECK(argon2_set_block(st, i, 1, in) == 0);
    }

    copy = (block*)malloc(st->size);
    assert(copy != NULL);
    memcpy(copy, st->memory, st->size);

    /* argon2_set_block() */
    CHECK(argon2_set_block(NULL, 0, 0, in) == ERR_NULL);
    CHECK(argon2_set_block(st, 0, 0, NULL) == ERR_NULL);
    CHECK(argon2_set_block(st, 3, 0, in) == ERR_VALUE);
    CHECK(argon2_set_block(st, 0, 8, in) == ERR_VALUE);
    CHECK(argon2_set_block(st, 0, 0xFFFFFFFFU, in) == ERR_VALUE);

    /* argon2_fill_segment() */
    CHECK(argon2_fill_segment(NULL, 0, 0, 0) == ERR_NULL);
    CHECK(argon2_fill_segment(st, 2, 0, 0) == ERR_VALUE);
    CHECK(argon2_fill_segment(st, 0, 4, 0) == ERR_VALUE);
    CHECK(argon2_fill_segment(st, 0, 0, 3) == ERR_VALUE);
    CHECK(argon2_fill_segment(st, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU) == ERR_VALUE);

    /* argon2_get_final_block() */
    CHECK(argon2_get_final_block(NULL, out) == ERR_NULL);
    CHECK(argon2_get_final_block(st, NULL) == ERR_NULL);

    CHECK(memcmp(copy, st->memory, st->size) == 0);

    /* The smallest memory, filled with the checks on each segment */
    fill_memory_checked(st);
    CHECK(argon2_get_final_block(st, out) == 0);

    CHECK(argon2_destroy(NULL) == ERR_NULL);
    CHECK(argon2_destroy(st) == 0);
    free(copy);
}

/* The poisoning really happens (with ASan), so the read checks are not void */
static void test_poisoning(void)
{
    argon2_state *st;

    CHECK(argon2_new(&st, 32, 2, 1, ARGON2_D) == 0);
    poison_forbidden(st, 0, 1, 0);
#if defined(HAVE_ASAN)
    CHECK(IS_POISONED(&st->memory[16 + 4]));    /* lane 1, slice 1 */
    CHECK(IS_POISONED(&st->memory[8]));         /* lane 0, slice 2 */
    CHECK(!IS_POISONED(&st->memory[4]));        /* lane 0, slice 1: its own segment */
    CHECK(!IS_POISONED(&st->memory[16]));       /* lane 1, slice 0 */
#endif
    UNPOISON(st->memory, st->size);
    CHECK(argon2_destroy(st) == 0);
}

int main(void)
{
#if defined(TEST_ARGON2_AVX2)
    if (!__builtin_cpu_supports("avx2")) {
        /* In CI on x86-64, the test must run (ARGON2_REQUIRE_AVX2 is set) */
        const char *required = getenv("ARGON2_REQUIRE_AVX2");

        if (required != NULL && required[0] != 0) {
            printf("Failed: the CPU does not support AVX2, but ARGON2_REQUIRE_AVX2 is set\n");
            return 1;
        }
        printf("Skipped: the CPU does not support AVX2\n");
        return 0;
    }
#endif

    test_poisoning();
    test_fill_block();
    test_errors();
    test_rfc9106();
    test_libargon2();

    if (failures) {
        printf("%d checks failed\n", failures);
        return 1;
    }
#if defined(HAVE_ASAN)
    printf("All tests passed (with ASan: the forbidden reads are checked)\n");
#else
    printf("All tests passed (without ASan: only the writes are checked)\n");
#endif
    return 0;
}
