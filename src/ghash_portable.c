/*
 *  ghash_portable.c: GHASH in portable, constant-time C
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */

#include "common.h"
#include "endianess.h"

FAKE_INIT(ghash_portable)

/**
 * The multiplication in GF(2^128) does not use tables: it follows the
 * technique described by Thomas Pornin for BearSSL, in
 * https://bearssl.org/constanttime.html#ghash-for-gcm
 *
 * No memory access and no branch depends on secret data: the code is
 * constant-time as long as the CPU multiplies integers in constant time.
 *
 * A carry-less product is computed with ordinary integer multiplications,
 * on operands where only one bit every four is kept ("words with holes").
 * Bit k of the product of two such operands is the sum of the bit
 * products x_i*y_j with i+j=k: each sum has few terms, so its carries
 * stay in the 3 bits of the hole, and they are masked away.
 *
 * A field element is an array of words, least significant first, where
 * the 16 bytes of GHASH are read as a big endian integer. GHASH reflects
 * the bits (the leftmost one is the coefficient of x^0): the carry-less
 * product of two such integers is the reflection of the product of
 * the polynomials, over 255 bits.
 *
 * The word size is picked at compile time:
 *  - on 64-bit systems, 64x64->64 multiplications. They only give the
 *    lower half of a carry-less product: the upper half is the reflection
 *    of the lower half of the product of the reflected operands.
 *  - on 32-bit systems, 32x32->64 multiplications, which take one
 *    instruction (64x64 multiplications take three).
 */

#if SYS_BITS == 64

typedef uint64_t word_t;
#define WORD_BITS 64
#define LOAD_WORD_BIG(p) LOAD_U64_BIG(p)
#define STORE_WORD_BIG(p, w) STORE_U64_BIG(p, w)

#elif SYS_BITS == 32

typedef uint32_t word_t;
#define WORD_BITS 32
#define LOAD_WORD_BIG(p) LOAD_U32_BIG(p)
#define STORE_WORD_BIG(p, w) STORE_U32_BIG(p, w)

#else
#error You must define the macro SYS_BITS
#endif

#define N_WORDS (128 / WORD_BITS)

/** Masks for the four classes of bits, by position modulo 4 **/
#define HOLES(m) ((word_t)(m) * (word_t)(~(word_t)0 / 15))

/**
 * Bits in class i of a product come from the bits in class j of x
 * and the bits in class i-j (mod 4) of y, for all j.
 */
#define CLASS_SUM(T, xm, ym, i) ( \
        ((T)(xm)[0] * (ym)[(i) & 3]) ^ ((T)(xm)[1] * (ym)[((i)-1) & 3]) ^ \
        ((T)(xm)[2] * (ym)[((i)-2) & 3]) ^ ((T)(xm)[3] * (ym)[((i)-3) & 3]) )

#if SYS_BITS == 64

/**
 * The expanded key: values derived from H once, and used for every block.
 *
 *  h[0]   the lower word of H (its last 8 bytes)
 *  h[1]   the upper word of H (its first 8 bytes)
 *  h[2]   h[0] ^ h[1], for the middle term of Karatsuba
 *  hr[i]  reflect(h[i]), to compute the upper halves of the products
 *         (see product())
 */
typedef struct {
    word_t h[3];
    word_t hr[3];
} t_exp_key;

/** Lower 64 bits of the carry-less product of x and y **/
static inline word_t clmul_low(word_t x, word_t y)
{
    const word_t xm[4] = { x & HOLES(1), x & HOLES(2), x & HOLES(4), x & HOLES(8) };
    const word_t ym[4] = { y & HOLES(1), y & HOLES(2), y & HOLES(4), y & HOLES(8) };

    /** Each bit of the result is the sum of at most 15 bit products **/
    return (CLASS_SUM(word_t, xm, ym, 0) & HOLES(1)) |
           (CLASS_SUM(word_t, xm, ym, 1) & HOLES(2)) |
           (CLASS_SUM(word_t, xm, ym, 2) & HOLES(4)) |
           (CLASS_SUM(word_t, xm, ym, 3) & HOLES(8));
}

/** Swap adjacent groups of n bits, where mask selects the lower groups **/
static inline word_t swap_groups(word_t x, word_t mask, unsigned n)
{
    return ((x & mask) << n) | ((x >> n) & mask);
}

/**
 * Reverse the order of the bits: bit i moves to bit 63-i.
 * It takes log2(64) = 6 steps, which swap adjacent groups of 1, 2, 4, 8,
 * 16 and finally 32 bits.
 *
 * clmul_low() only gives bits 0..63 of the 127-bit product of a and b.
 * In reflect(a), bit i of a is at 63-i: the product of bit i of a and
 * bit j of b lands at (63-i)+(63-j) = 126-(i+j). So, the lower 64 bits
 * of the product of reflect(a) and reflect(b) hold bits 126..63 of the
 * product of a and b. Once reflected, they are in order (bits 63..126 in
 * positions 0..63), and a shift right by one bit drops bit 63, which is
 * already in the lower word: the result is the upper word.
 *
 * The reflection is linear: reflect(a ^ b) = reflect(a) ^ reflect(b).
 */
static inline word_t reflect(word_t x)
{
    x = swap_groups(x, 0x5555555555555555ULL, 1);
    x = swap_groups(x, 0x3333333333333333ULL, 2);
    x = swap_groups(x, 0x0F0F0F0F0F0F0F0FULL, 4);
    x = swap_groups(x, 0x00FF00FF00FF00FFULL, 8);
    x = swap_groups(x, 0x0000FFFF0000FFFFULL, 16);
    return (x << 32) | (x >> 32);
}

static void expand_key(t_exp_key *key, const word_t h[N_WORDS])
{
    unsigned i;

    key->h[0] = h[0];
    key->h[1] = h[1];
    key->h[2] = h[0] ^ h[1];
    for (i=0; i<3; i++) {
        key->hr[i] = reflect(key->h[i]);
    }
}

/**
 * 256-bit product of y and H (in fact, 255 bits), without reduction.
 *
 * Karatsuba, where addition and subtraction are both XOR:
 *
 *  Y*H = P1*2^128 ^ M*2^64 ^ P0
 *
 * with P0 = y0*h0, P1 = y1*h1 and M = (y0^y1)*(h0^h1) ^ P0 ^ P1:
 * three products of words instead of four.
 * Each product of words takes two calls to clmul_low() (16 multiplications
 * each): one for the lower word, one for the upper word.
 */
static void product(word_t z[2*N_WORDS], const word_t y[N_WORDS], const t_exp_key *key)
{
    /** The Karatsuba operands of y, like key->h[] for H **/
    const word_t a[3] = { y[0], y[1], y[0] ^ y[1] };
    word_t ar[3], lo[3], hi[3];

    /** Their reflections (by linearity for the third one) **/
    ar[0] = reflect(a[0]);
    ar[1] = reflect(a[1]);
    ar[2] = ar[0] ^ ar[1];

    /** Lower words of the three products **/
    lo[0] = clmul_low(a[0], key->h[0]);
    lo[1] = clmul_low(a[1], key->h[1]);
    lo[2] = clmul_low(a[2], key->h[2]);

    /** Upper words (63 bits), from the reflected operands (see reflect()) **/
    hi[0] = reflect(clmul_low(ar[0], key->hr[0])) >> 1;
    hi[1] = reflect(clmul_low(ar[1], key->hr[1])) >> 1;
    hi[2] = reflect(clmul_low(ar[2], key->hr[2])) >> 1;

    /** (hi[2]:lo[2]) becomes the middle term M **/
    lo[2] ^= lo[0] ^ lo[1];
    hi[2] ^= hi[0] ^ hi[1];

    /** P0, then M one word up, then P1 two words up (bit 63 of z[3] is 0) **/
    z[0] = lo[0];
    z[1] = hi[0] ^ lo[2];
    z[2] = lo[1] ^ hi[2];
    z[3] = hi[1];
}

#else

/**
 * The expanded key: the operands of H for a two-level Karatsuba
 * (see karatsuba_operands()), computed once and used for every block.
 * With w0..w3 the words of H (w0 being its last 4 bytes):
 *
 *  h[0..2]  w0, w1, w0^w1                the lower half of H
 *  h[3..5]  w2, w3, w2^w3                the upper half of H
 *  h[6..8]  w0^w2, w1^w3, w0^w1^w2^w3   the sum of the two halves
 */
typedef struct {
    word_t h[9];
} t_exp_key;

/** Carry-less product of x and y, as the upper and the lower word **/
static inline void clmul(word_t *hi, word_t *lo, word_t x, word_t y)
{
    const word_t xm[4] = { x & HOLES(1), x & HOLES(2), x & HOLES(4), x & HOLES(8) };
    const word_t ym[4] = { y & HOLES(1), y & HOLES(2), y & HOLES(4), y & HOLES(8) };
    const uint64_t holes = 0x1111111111111111ULL;
    uint64_t result;

    /** Each bit of the result is the sum of at most 8 bit products **/
    result = (CLASS_SUM(uint64_t, xm, ym, 0) & holes) |
             (CLASS_SUM(uint64_t, xm, ym, 1) & (holes << 1)) |
             (CLASS_SUM(uint64_t, xm, ym, 2) & (holes << 2)) |
             (CLASS_SUM(uint64_t, xm, ym, 3) & (holes << 3));

    *lo = (word_t)result;
    *hi = (word_t)(result >> 32);
}

/**
 * Operands for a two-level Karatsuba, from the four words w[]:
 * the lower half (0..2), the upper half (3..5), and their sum (6..8),
 * each as its lower word, its upper word, and their sum.
 */
static void karatsuba_operands(word_t a[9], const word_t w[N_WORDS])
{
    unsigned i;

    for (i=0; i<2; i++) {
        a[3*i] = w[2*i];
        a[3*i+1] = w[2*i+1];
        a[3*i+2] = w[2*i] ^ w[2*i+1];
    }
    for (i=0; i<3; i++) {
        a[6+i] = a[i] ^ a[3+i];
    }
}

static void expand_key(t_exp_key *key, const word_t h[N_WORDS])
{
    karatsuba_operands(key->h, h);
}

/** Karatsuba: 64x64 carry-less product, from the operands in x[] and y[] **/
static void product_64(word_t r[4], const word_t x[3], const word_t y[3])
{
    word_t l0, l1, h0, h1, m0, m1;

    clmul(&l1, &l0, x[0], y[0]);
    clmul(&h1, &h0, x[1], y[1]);
    clmul(&m1, &m0, x[2], y[2]);
    m0 ^= l0 ^ h0;
    m1 ^= l1 ^ h1;

    r[0] = l0;
    r[1] = l1 ^ m0;
    r[2] = h0 ^ m1;
    r[3] = h1;
}

/**
 * 256-bit product of y and H (in fact, 255 bits), without reduction.
 *
 * Karatsuba on the 64-bit halves, where addition and subtraction are
 * both XOR:
 *
 *  Y*H = P1*2^128 ^ M*2^64 ^ P0
 *
 * with P0 and P1 the products of the lower and of the upper halves,
 * and M = (y0^y1)*(h0^h1) ^ P0 ^ P1 (y0, y1, h0, h1 being the halves).
 * Each of the three 64x64 products is again a Karatsuba (product_64()),
 * for a total of nine calls to clmul() (16 multiplications each).
 */
static void product(word_t z[2*N_WORDS], const word_t y[N_WORDS], const t_exp_key *key)
{
    word_t a[9], lo[4], hi[4], mid[4];
    unsigned i;

    /** The operands of y, with the same layout as key->h[] **/
    karatsuba_operands(a, y);
    product_64(lo, &a[0], &key->h[0]);
    product_64(hi, &a[3], &key->h[3]);
    product_64(mid, &a[6], &key->h[6]);

    /** mid becomes the middle term M; P0 and P1 go to the lower and the upper half of z **/
    for (i=0; i<4; i++) {
        mid[i] ^= lo[i] ^ hi[i];
        z[i] = lo[i];
        z[i+4] = hi[i];
    }
    /** M goes two words up **/
    for (i=0; i<4; i++) {
        z[i+2] ^= mid[i];
    }
}

#endif

/** Word w shifted left by one bit, taking the top bit of the word below **/
static inline word_t shl1(word_t w, word_t below)
{
    return (w << 1) | (below >> (WORD_BITS-1));
}

/**
 * Reduction of word i (in the lower 128 bits of z), with
 * x^128 = x^7 + x^2 + x + 1: the coefficient in bit b (b < 128)
 * is moved to bits b+128, b+127, b+126 and b+121.
 * Bits that land again below 128 are in word i-1+N_WORDS, which
 * must be folded later (if it is in the lower half).
 */
static inline void fold(word_t z[2*N_WORDS], unsigned i)
{
    word_t t = z[i];

    z[i+N_WORDS] ^= t ^ (t >> 1) ^ (t >> 2) ^ (t >> 7);
    z[i+N_WORDS-1] ^= (t << (WORD_BITS-1)) ^ (t << (WORD_BITS-2)) ^ (t << (WORD_BITS-7));
}

/**
 * y = y * H in GF(2^128)
 *
 * The steps on z[] are written out, without loops: this way, compilers
 * keep z[] in registers (a loop would leave it on the stack).
 */
static void gf_mult(word_t y[N_WORDS], const t_exp_key *key)
{
    word_t z[2*N_WORDS];

    product(z, y, key);

    /**
     * The 255-bit product holds the coefficient of x^k in bit 254-k:
     * with a shift by one bit, the coefficients of x^0..x^127 are
     * in the upper 128 bits, and those of x^128..x^255 in the lower ones.
     */
#if N_WORDS == 2
    z[3] = shl1(z[3], z[2]);
    z[2] = shl1(z[2], z[1]);
    z[1] = shl1(z[1], z[0]);
    z[0] <<= 1;

    fold(z, 0);
    fold(z, 1);

    y[0] = z[2];
    y[1] = z[3];
#else
    z[7] = shl1(z[7], z[6]);
    z[6] = shl1(z[6], z[5]);
    z[5] = shl1(z[5], z[4]);
    z[4] = shl1(z[4], z[3]);
    z[3] = shl1(z[3], z[2]);
    z[2] = shl1(z[2], z[1]);
    z[1] = shl1(z[1], z[0]);
    z[0] <<= 1;

    fold(z, 0);
    fold(z, 1);
    fold(z, 2);
    fold(z, 3);

    y[0] = z[4];
    y[1] = z[5];
    y[2] = z[6];
    y[3] = z[7];
#endif
}

static void load_element(word_t w[N_WORDS], const uint8_t in[16])
{
    unsigned i;

    for (i=0; i<N_WORDS; i++) {
        w[i] = LOAD_WORD_BIG(in + 16 - (i+1)*(WORD_BITS/8));
    }
}

static void store_element(uint8_t out[16], const word_t w[N_WORDS])
{
    unsigned i;

    for (i=0; i<N_WORDS; i++) {
        word_t t = w[i];

        STORE_WORD_BIG(out + 16 - (i+1)*(WORD_BITS/8), t);
    }
}

/** Process len bytes (multiple of 16), with y as the accumulator **/
static void ghash_blocks(uint8_t y[16], const uint8_t data[], size_t len, const t_exp_key *key)
{
    word_t yw[N_WORDS], x[N_WORDS];
    size_t i;
    unsigned j;

    load_element(yw, y);
    for (i=0; i<len; i+=16) {
        load_element(x, data + i);
        for (j=0; j<N_WORDS; j++) {
            yw[j] ^= x[j];
        }
        gf_mult(yw, key);
    }
    store_element(y, yw);
}

static void expand_key_bytes(t_exp_key *key, const uint8_t h[16])
{
    word_t hw[N_WORDS];

    load_element(hw, h);
    expand_key(key, hw);
}

/**
 * Compute the GHASH of a piece of data given an arbitrary Y_0,
 * as specified in NIST SP 800 38D.
 *
 * \param y_out      The resulting GHASH (16 bytes).
 * \param block_data Pointer to the data to hash.
 * \param len        Length of the data to hash (multiple of 16).
 * \param y_in       The initial Y (Y_0, 16 bytes).
 * \param exp_key    The expanded hash key.
 *
 * y_out and y_int can point to the same buffer.
 */
EXPORT_SYM int ghash_portable(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t len,
        const uint8_t y_in[16],
        const t_exp_key *exp_key
        )
{
    if (NULL==y_out || NULL==block_data || NULL==y_in || NULL==exp_key)
        return ERR_NULL;

    if (len % 16)
        return ERR_NOT_ENOUGH_DATA;

    memmove(y_out, y_in, 16);
    ghash_blocks(y_out, block_data, len, exp_key);

    return 0;
}

/**
 * Like ghash_portable(), but for the len bytes at the given offset
 * in block_data[]. Several threads can call it at the same time,
 * with the same expanded key.
 */
EXPORT_SYM int ghash_at_portable(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t offset,
        size_t len,
        const uint8_t y_in[16],
        const t_exp_key *exp_key
        )
{
    if (NULL==block_data)
        return ERR_NULL;

    return ghash_portable(y_out, block_data + offset, len, y_in, exp_key);
}

/**
 * Multiply two arbitrary elements of GF(2**128).
 * out can point to the same buffer as x or y.
 */
static void gcm_mult(uint8_t out[16], const uint8_t x[16], const uint8_t y[16])
{
    t_exp_key key;
    static const uint8_t zero[16] = { 0 };

    expand_key_bytes(&key, y);
    memmove(out, x, 16);
    /** (0 ^ x) * y **/
    ghash_blocks(out, zero, 16, &key);
}

/**
 * Combine the GHASH of two consecutive pieces of data:
 *
 *  y_out = y_in * H^n_blocks + g
 *
 * where y_in is the GHASH of the first piece, and g is the GHASH of
 * the second piece (n_blocks long), computed with Y_0 = 0.
 *
 * y_out can point to the same buffer as y_in or g.
 */
EXPORT_SYM int ghash_combine_portable(
        uint8_t y_out[16],
        const uint8_t y_in[16],
        size_t n_blocks,
        const uint8_t g[16],
        const t_exp_key *exp_key
        )
{
    uint8_t y[16], b[16];
    static const uint8_t one[16] = { 0x80 };
    unsigned i;

    if (NULL==y_out || NULL==y_in || NULL==g || NULL==exp_key)
        return ERR_NULL;

    /** b = H, as 1 * H (the element 1 is x^0, the leftmost bit) **/
    memset(b, 0, 16);
    ghash_blocks(b, one, 16, exp_key);

    /** Square and multiply, from the least significant bit of n_blocks **/
    memcpy(y, y_in, 16);
    while (n_blocks > 0) {
        if (n_blocks & 1) {
            gcm_mult(y, y, b);
        }
        n_blocks >>= 1;
        if (n_blocks > 0) {
            gcm_mult(b, b, b);
        }
    }

    for (i=0; i<16; i++) {
        y_out[i] = y[i] ^ g[i];
    }
    return 0;
}

/**
 * Expand the GHASH key H.
 */
EXPORT_SYM int ghash_expand_portable(const uint8_t h[16], t_exp_key **ghash_tables)
{
    t_exp_key *exp_key;

    if (NULL==h || NULL==ghash_tables)
        return ERR_NULL;

    *ghash_tables = exp_key = calloc(1, sizeof(t_exp_key));
    if (NULL == exp_key)
        return ERR_MEMORY;

    expand_key_bytes(exp_key, h);

    return 0;
}

EXPORT_SYM int ghash_destroy_portable(t_exp_key *ghash_tables)
{
    free(ghash_tables);
    return 0;
}
