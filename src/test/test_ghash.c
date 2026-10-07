#include "common.h"

/*
 * Tests of GHASH, for the portable and (if available) the CLMUL implementation:
 * ghash_*(), ghash_at_*() and ghash_combine_*().
 * The reference is a plain bit-by-bit multiplication in GF(2^128)
 * (NIST SP 800-38D, Algorithm 1), independent of both implementations.
 */

typedef int (*Expand)(const uint8_t h[16], void **exp_key);
typedef int (*Destroy)(void *exp_key);
typedef int (*Ghash)(uint8_t y_out[16], const uint8_t data[], size_t len, const uint8_t y_in[16], const void *exp_key);
typedef int (*GhashAt)(uint8_t y_out[16], const uint8_t data[], size_t offset, size_t len,
                       const uint8_t y_in[16], const void *exp_key);
typedef int (*Combine)(uint8_t y_out[16], const uint8_t y_in[16], size_t n_blocks, const uint8_t g[16],
                       const void *exp_key);

int ghash_expand_portable(const uint8_t h[16], void **exp_key);
int ghash_destroy_portable(void *exp_key);
int ghash_portable(uint8_t y_out[16], const uint8_t data[], size_t len, const uint8_t y_in[16], const void *exp_key);
int ghash_at_portable(uint8_t y_out[16], const uint8_t data[], size_t offset, size_t len,
                      const uint8_t y_in[16], const void *exp_key);
int ghash_combine_portable(uint8_t y_out[16], const uint8_t y_in[16], size_t n_blocks, const uint8_t g[16],
                           const void *exp_key);

#ifdef TEST_CLMUL
int ghash_expand_clmul(const uint8_t h[16], void **exp_key);
int ghash_destroy_clmul(void *exp_key);
int ghash_clmul(uint8_t y_out[16], const uint8_t data[], size_t len, const uint8_t y_in[16], const void *exp_key);
int ghash_at_clmul(uint8_t y_out[16], const uint8_t data[], size_t offset, size_t len,
                   const uint8_t y_in[16], const void *exp_key);
int ghash_combine_clmul(uint8_t y_out[16], const uint8_t y_in[16], size_t n_blocks, const uint8_t g[16],
                        const void *exp_key);
#endif

typedef struct {
    const char *name;
    Expand expand;
    Destroy destroy;
    Ghash ghash;
    GhashAt ghash_at;
    Combine combine;
} Implementation;

static const Implementation implementations[] = {
    { "portable", ghash_expand_portable, ghash_destroy_portable, ghash_portable,
      ghash_at_portable, ghash_combine_portable },
#ifdef TEST_CLMUL
    { "clmul", ghash_expand_clmul, ghash_destroy_clmul, ghash_clmul,
      ghash_at_clmul, ghash_combine_clmul },
#endif
};

/* ---- Reference ---- */

/** z = x * y in GF(2^128), with the bit order of GCM **/
static void ref_mult(uint8_t z[16], const uint8_t x[16], const uint8_t y[16])
{
    uint8_t v[16], r[16];
    unsigned i, j;

    memset(r, 0, 16);
    memcpy(v, y, 16);
    for (i=0; i<128; i++) {
        unsigned lsb;

        if ((x[i/8] >> (7 - i%8)) & 1) {
            for (j=0; j<16; j++)
                r[j] ^= v[j];
        }
        lsb = v[15] & 1;
        for (j=15; j>0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j-1] << 7));
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xE1;
    }
    memcpy(z, r, 16);
}

/** y_out = GHASH of len bytes (multiple of 16), starting from y_in **/
static void ref_ghash(uint8_t y_out[16], const uint8_t h[16], const uint8_t *data, size_t len, const uint8_t y_in[16])
{
    uint8_t y[16];
    size_t i, j;

    memcpy(y, y_in, 16);
    for (i=0; i<len; i+=16) {
        for (j=0; j<16; j++)
            y[j] ^= data[i+j];
        ref_mult(y, y, h);
    }
    memcpy(y_out, y, 16);
}

/** y_out = y_in * h^n xor g (square and multiply, from the most significant bit) **/
static void ref_combine(uint8_t y_out[16], const uint8_t h[16], const uint8_t y_in[16], uint64_t n, const uint8_t g[16])
{
    uint8_t p[16];  /** h^n **/
    int bit;
    unsigned j;

    memset(p, 0, 16);
    p[0] = 0x80;    /** The unit element **/
    for (bit=63; bit>=0; bit--) {
        ref_mult(p, p, p);
        if ((n >> bit) & 1)
            ref_mult(p, p, h);
    }
    ref_mult(y_out, y_in, p);
    for (j=0; j<16; j++)
        y_out[j] ^= g[j];
}

/* ---- Helpers ---- */

static uint32_t rng_state = 1;

static void random_bytes(uint8_t *out, size_t len)
{
    size_t i;

    for (i=0; i<len; i++) {
        rng_state = rng_state * 1103515245u + 12345u;
        out[i] = (uint8_t)(rng_state >> 16);
    }
}

static void *expand(const Implementation *imp, const uint8_t h[16])
{
    void *exp_key;

    assert(0 == imp->expand(h, &exp_key));
    return exp_key;
}

/* ---- Tests ---- */

/** NIST SP 800-38D, test case 2: GHASH(H, {}, C) **/
static void test_known_answer(const Implementation *imp)
{
    static const uint8_t h[16] = { 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                                   0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e };
    static const uint8_t data[32] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80 };
    static const uint8_t expected[16] = { 0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc,
                                          0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85 };
    uint8_t zero[16] = { 0 }, y[16];
    void *exp_key = expand(imp, h);

    assert(0 == imp->ghash(y, data, 32, zero, exp_key));
    assert(0 == memcmp(y, expected, 16));
    ref_ghash(y, h, data, 32, zero);
    assert(0 == memcmp(y, expected, 16));

    imp->destroy(exp_key);
}

/** ghash() of 0 to 20 blocks, which covers both the 4-block and the 1-block loop of CLMUL **/
static void test_ghash_lengths(const Implementation *imp)
{
    uint8_t h[16], y_in[16], data[16*20], y[16], y_ref[16];
    size_t len;
    void *exp_key;

    random_bytes(h, 16);
    random_bytes(y_in, 16);
    random_bytes(data, sizeof data);
    exp_key = expand(imp, h);

    for (len=0; len<=sizeof data; len+=16) {
        assert(0 == imp->ghash(y, data, len, y_in, exp_key));
        ref_ghash(y_ref, h, data, len, y_in);
        assert(0 == memcmp(y, y_ref, 16));
    }

    /** No data: y_out is y_in **/
    assert(0 == imp->ghash(y, data, 0, y_in, exp_key));
    assert(0 == memcmp(y, y_in, 16));

    /** y_out can be y_in **/
    memcpy(y, y_in, 16);
    assert(0 == imp->ghash(y, data, 16*7, y, exp_key));
    ref_ghash(y_ref, h, data, 16*7, y_in);
    assert(0 == memcmp(y, y_ref, 16));

    /** Only whole blocks **/
    assert(ERR_NOT_ENOUGH_DATA == imp->ghash(y, data, 15, y_in, exp_key));
    assert(ERR_NOT_ENOUGH_DATA == imp->ghash(y, data, 17, y_in, exp_key));

    imp->destroy(exp_key);
}

/** ghash_at() is ghash() on data + offset, for any offset (even unaligned) **/
static void test_ghash_at(const Implementation *imp)
{
    uint8_t h[16], y_in[16], data[16*12 + 16], y[16], y_ref[16];
    size_t offset, len;
    void *exp_key;

    random_bytes(h, 16);
    random_bytes(y_in, 16);
    random_bytes(data, sizeof data);
    exp_key = expand(imp, h);

    for (offset=0; offset<=16; offset++) {
        for (len=0; len<=16*12; len+=16) {
            assert(0 == imp->ghash_at(y, data, offset, len, y_in, exp_key));
            ref_ghash(y_ref, h, data + offset, len, y_in);
            assert(0 == memcmp(y, y_ref, 16));
        }
    }

    /** y_out can be y_in **/
    memcpy(y, y_in, 16);
    assert(0 == imp->ghash_at(y, data, 32, 64, y, exp_key));
    ref_ghash(y_ref, h, data + 32, 64, y_in);
    assert(0 == memcmp(y, y_ref, 16));

    assert(ERR_NOT_ENOUGH_DATA == imp->ghash_at(y, data, 0, 31, y_in, exp_key));

    imp->destroy(exp_key);
}

/** ghash_combine() against the reference, for exponents with all kinds of bit patterns **/
static void test_combine_values(const Implementation *imp)
{
    uint8_t h[16], y_in[16], g[16], y[16], y_ref[16];
    uint64_t exponents[64*3 + 8];
    unsigned i, n_exp = 0;
    void *exp_key;

    random_bytes(h, 16);
    random_bytes(y_in, 16);
    random_bytes(g, 16);
    exp_key = expand(imp, h);

    for (i=0; i<20; i++)
        exponents[n_exp++] = i;
    for (i=5; i<(unsigned)(8*sizeof(size_t)); i++) {
        exponents[n_exp++] = (uint64_t)1 << i;          /** 2^i **/
        exponents[n_exp++] = ((uint64_t)1 << i) - 1;    /** all ones **/
        exponents[n_exp++] = ((uint64_t)1 << i) + 1;
    }
    exponents[n_exp++] = (uint64_t)SIZE_MAX;
    exponents[n_exp++] = (uint64_t)SIZE_MAX - 1;
    exponents[n_exp++] = (uint64_t)(SIZE_MAX / 3);      /** 0101... **/

    for (i=0; i<n_exp; i++) {
        assert(0 == imp->combine(y, y_in, (size_t)exponents[i], g, exp_key));
        ref_combine(y_ref, h, y_in, exponents[i], g);
        assert(0 == memcmp(y, y_ref, 16));
    }

    imp->destroy(exp_key);
}

/** Special values of H, y_in and g **/
static void test_combine_special(const Implementation *imp)
{
    uint8_t zero[16] = { 0 }, one[16] = { 0x80 }, h[16], y_in[16], g[16], y[16], y_ref[16];
    unsigned j;
    void *exp_key;

    random_bytes(h, 16);
    random_bytes(y_in, 16);
    random_bytes(g, 16);

    /** n = 0: y_in xor g **/
    exp_key = expand(imp, h);
    assert(0 == imp->combine(y, y_in, 0, g, exp_key));
    for (j=0; j<16; j++)
        assert(y[j] == (y_in[j] ^ g[j]));

    /** y_in = 0: g, for any n **/
    assert(0 == imp->combine(y, zero, 12345, g, exp_key));
    assert(0 == memcmp(y, g, 16));

    /** g = 0: y_in * H^n, which is the GHASH of n zero blocks **/
    {
        uint8_t blocks[16*9] = { 0 };

        assert(0 == imp->combine(y, y_in, 9, zero, exp_key));
        ref_ghash(y_ref, h, blocks, sizeof blocks, y_in);
        assert(0 == memcmp(y, y_ref, 16));
    }

    /** y_out can be y_in or g **/
    memcpy(y, y_in, 16);
    assert(0 == imp->combine(y, y, 77, g, exp_key));
    ref_combine(y_ref, h, y_in, 77, g);
    assert(0 == memcmp(y, y_ref, 16));
    memcpy(y, g, 16);
    assert(0 == imp->combine(y, y_in, 77, y, exp_key));
    assert(0 == memcmp(y, y_ref, 16));
    imp->destroy(exp_key);

    /** H = 0: y_in xor g for n = 0, g otherwise **/
    exp_key = expand(imp, zero);
    assert(0 == imp->combine(y, y_in, 0, g, exp_key));
    for (j=0; j<16; j++)
        assert(y[j] == (y_in[j] ^ g[j]));
    assert(0 == imp->combine(y, y_in, 1, g, exp_key));
    assert(0 == memcmp(y, g, 16));
    assert(0 == imp->combine(y, y_in, SIZE_MAX, g, exp_key));
    assert(0 == memcmp(y, g, 16));
    imp->destroy(exp_key);

    /** H = 1: y_in xor g for any n **/
    exp_key = expand(imp, one);
    assert(0 == imp->combine(y, y_in, SIZE_MAX, g, exp_key));
    for (j=0; j<16; j++)
        assert(y[j] == (y_in[j] ^ g[j]));
    imp->destroy(exp_key);
}

/** Hashing data in pieces with ghash_at() and combining them gives the GHASH of the whole data **/
static void test_split_and_combine(const Implementation *imp)
{
    uint8_t h[16], y_in[16], data[16*40], y_full[16], y[16], part[16], zero[16] = { 0 };
    unsigned trial;
    void *exp_key;

    random_bytes(h, 16);
    random_bytes(y_in, 16);
    random_bytes(data, sizeof data);
    exp_key = expand(imp, h);

    assert(0 == imp->ghash(y_full, data, sizeof data, y_in, exp_key));

    for (trial=0; trial<200; trial++) {
        size_t start = 0;

        /** The first piece starts from y_in, the others from zero, and are then combined **/
        memcpy(y, y_in, 16);
        while (start < sizeof data) {
            uint8_t r;
            size_t n_blocks;

            random_bytes(&r, 1);
            n_blocks = MIN((size_t)(r % 9), (sizeof data - start) / 16);   /** 0 to 8 blocks **/
            if (0 == start) {
                assert(0 == imp->ghash_at(y, data, 0, n_blocks*16, y, exp_key));
            } else {
                assert(0 == imp->ghash_at(part, data, start, n_blocks*16, zero, exp_key));
                assert(0 == imp->combine(y, y, n_blocks, part, exp_key));
            }
            start += n_blocks*16;
        }
        assert(0 == memcmp(y, y_full, 16));
    }

    imp->destroy(exp_key);
}

/** Both implementations agree **/
static void test_implementations_agree(void)
{
#ifdef TEST_CLMUL
    uint8_t h[16], y_in[16], g[16], data[16*33], y1[16], y2[16];
    void *k1, *k2;
    unsigned trial;

    for (trial=0; trial<50; trial++) {
        uint8_t r[8];
        size_t n;

        random_bytes(h, 16);
        random_bytes(y_in, 16);
        random_bytes(g, 16);
        random_bytes(data, sizeof data);
        random_bytes(r, sizeof r);
        memcpy(&n, r, sizeof n);

        k1 = expand(&implementations[0], h);
        k2 = expand(&implementations[1], h);
        assert(0 == implementations[0].ghash(y1, data, sizeof data, y_in, k1));
        assert(0 == implementations[1].ghash(y2, data, sizeof data, y_in, k2));
        assert(0 == memcmp(y1, y2, 16));
        assert(0 == implementations[0].combine(y1, y_in, n, g, k1));
        assert(0 == implementations[1].combine(y2, y_in, n, g, k2));
        assert(0 == memcmp(y1, y2, 16));
        implementations[0].destroy(k1);
        implementations[1].destroy(k2);
    }
#endif
}

static void test_null(const Implementation *imp)
{
    uint8_t h[16] = { 1 }, data[32] = { 0 }, y[16];
    void *exp_key;

    assert(ERR_NULL == imp->expand(NULL, &exp_key));
    assert(ERR_NULL == imp->expand(h, NULL));
    exp_key = expand(imp, h);

    assert(ERR_NULL == imp->ghash(NULL, data, 16, h, exp_key));
    assert(ERR_NULL == imp->ghash(y, NULL, 16, h, exp_key));
    assert(ERR_NULL == imp->ghash(y, data, 16, NULL, exp_key));
    assert(ERR_NULL == imp->ghash(y, data, 16, h, NULL));

    assert(ERR_NULL == imp->ghash_at(NULL, data, 0, 16, h, exp_key));
    assert(ERR_NULL == imp->ghash_at(y, NULL, 0, 16, h, exp_key));
    assert(ERR_NULL == imp->ghash_at(y, data, 0, 16, NULL, exp_key));
    assert(ERR_NULL == imp->ghash_at(y, data, 0, 16, h, NULL));

    assert(ERR_NULL == imp->combine(NULL, h, 1, h, exp_key));
    assert(ERR_NULL == imp->combine(y, NULL, 1, h, exp_key));
    assert(ERR_NULL == imp->combine(y, h, 1, NULL, exp_key));
    assert(ERR_NULL == imp->combine(y, h, 1, h, NULL));

    imp->destroy(exp_key);
}

int main(void)
{
    unsigned i;

    for (i=0; i<sizeof implementations / sizeof implementations[0]; i++) {
        const Implementation *imp = &implementations[i];

        test_known_answer(imp);
        test_ghash_lengths(imp);
        test_ghash_at(imp);
        test_combine_values(imp);
        test_combine_special(imp);
        test_split_and_combine(imp);
        test_null(imp);
    }
    test_implementations_agree();

    return 0;
}
