/*
 * An implementation of the SHA3 (Keccak) hash function family.
 *
 * Algorithm specifications: http://keccak.noekeon.org/
 * NIST Announcement:
 * http://csrc.nist.gov/groups/ST/hash/sha-3/winner_sha-3.html
 *
 * Written in 2013 by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain. To
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

#include <string.h>
#include <assert.h>
#include "common.h"
#include "endianess.h"

/*
 * Another module can reuse this code by including this file:
 *  - if KECCAK_EMBEDDED is defined, this file does not define the module
 *    init function nor exports any symbol (see k12.c). The functions
 *    are inline so that unused ones raise no warnings.
 *  - if KECCAK_MODULE is defined, the functions are exported from the
 *    module with that name (see keccak_avx2_bmi2.c).
 *
 * See KECCAK_K12.txt for which file includes which, and the resulting modules.
 */
#ifdef KECCAK_EMBEDDED
#define KECCAK_API static inline
#else
#ifndef KECCAK_MODULE
#define KECCAK_MODULE keccak
#endif
FAKE_INIT(KECCAK_MODULE)
#define KECCAK_API EXPORT_SYM
#endif

#define KECCAK_F1600_STATE 200

typedef struct
{
    uint64_t state[25];

    /*  The buffer is as long as the state,
     *  but only 'rate' bytes will be used.
     */
    uint8_t  buf[KECCAK_F1600_STATE];

    /*  When absorbing, this is the number of bytes in buf that
     *  are coming from the message and outstanding.
     *  When squeezing, this is the remaining number of bytes
     *  that can be used as digest.
     */
    unsigned valid_bytes;

    /* All values in bytes */
    unsigned capacity;
    unsigned rate;

    uint8_t  squeezing;
    uint8_t  rounds;
} keccak_state;

#undef ROL64
#define ROL64(x,y) ((((x) << (y)) | (x) >> (64-(y))) & 0xFFFFFFFFFFFFFFFFULL)

static void keccak_function (uint64_t *state, unsigned rounds);

KECCAK_API int keccak_reset(keccak_state *state)
{
    if (NULL == state)
        return ERR_NULL;

    memset(state->state, 0, sizeof(state->state));
    memset(state->buf, 0, sizeof(state->buf));
    state->valid_bytes = 0;
    state->squeezing = 0;

    return 0;
}

static void keccak_absorb_internal (keccak_state *self)
{
    unsigned i,j;
    uint64_t d;

    for (i=j=0; j < self->rate; ++i, j += 8) {
        d = LOAD_U64_LITTLE(self->buf + j);
        self->state[i] ^= d;
    }
}

static void
keccak_squeeze_internal (keccak_state *self)
{
    unsigned i, j;

    for (i=j=0; j < self->rate; ++i, j += 8) {
        STORE_U64_LITTLE(self->buf+j, self->state[i]);
    }
}

static int keccak_check_params(size_t capacity_bytes, uint8_t rounds)
{
    if (capacity_bytes >= KECCAK_F1600_STATE)
        return ERR_DIGEST_SIZE;

    /* The rate must be a whole number of 64-bit words */
    if (capacity_bytes % 8 != 0)
        return ERR_DIGEST_SIZE;

    if ((rounds != 12) && (rounds != 24))
        return ERR_NR_ROUNDS;

    return 0;
}

/* Set an all-zero state up, with parameters already checked */
static void keccak_init_state(keccak_state *ks, size_t capacity_bytes, uint8_t rounds)
{
    ks->capacity  = (unsigned)capacity_bytes;

    ks->rate      = KECCAK_F1600_STATE - ks->capacity;

    ks->squeezing = 0;
    ks->rounds    = rounds;
}

KECCAK_API int keccak_init (keccak_state **state,
                            size_t capacity_bytes,
                            uint8_t rounds)
{
    keccak_state *ks;
    int result;

    if (NULL == state) {
        return ERR_NULL;
    }

    result = keccak_check_params(capacity_bytes, rounds);
    if (result)
        return result;

    *state = ks = (keccak_state*) calloc(1, sizeof(keccak_state));
    if (NULL == ks)
        return ERR_MEMORY;

    keccak_init_state(ks, capacity_bytes, rounds);

    return 0;
}

KECCAK_API int keccak_destroy(keccak_state *state)
{
    free(state);
    return 0;
}

KECCAK_API int keccak_absorb (keccak_state *self,
                              const uint8_t *in,
                              size_t length)
{
    unsigned valid_bytes;

    if (NULL==self || NULL==in)
        return ERR_NULL;

    if (self->squeezing != 0)
        return ERR_UNKNOWN;

    /*
     * Read the position in buf[] only once, and check it: if several
     * threads used the object at once (not supported), the state could
     * be inconsistent, but buf[] must never overflow.
     * (The rate never changes after keccak_init()).
     */
    valid_bytes = self->valid_bytes;
    if (valid_bytes >= self->rate)
        return ERR_STATE;

    while (length > 0) {
        unsigned tc;
        unsigned left;

        /* Fast path: XOR whole blocks straight from the input */
        /* No need to copy them into self->buf first */
        if (valid_bytes == 0 && length >= self->rate) {
            unsigned i, j;

            for (i=j=0; j < self->rate; ++i, j += 8) {
                self->state[i] ^= LOAD_U64_LITTLE(in + j);
            }
            keccak_function(self->state, self->rounds);
            in     += self->rate;
            length -= self->rate;
            continue;
        }

        left = self->rate - valid_bytes;
        tc = (unsigned) MIN(length, left);
        memcpy(self->buf + valid_bytes, in, tc);

        valid_bytes       += tc;
        in                += tc;
        length            -= tc;

        if (valid_bytes == self->rate) {
            keccak_absorb_internal (self);
            keccak_function(self->state, self->rounds);
            valid_bytes = 0;
        }
    }

    self->valid_bytes = valid_bytes;
    return 0;
}

static int keccak_finish (keccak_state *self, uint8_t padding)
{
    unsigned valid_bytes;

    /* Read once and check (see keccak_absorb) */
    valid_bytes = self->valid_bytes;
    if (valid_bytes >= self->rate)
        return ERR_STATE;

    /* Padding */
    memset(self->buf + valid_bytes, 0, self->rate - valid_bytes);
    self->buf[valid_bytes] = padding;
    self->buf[self->rate-1] |= 0x80;

    /* Final absorb */
    keccak_absorb_internal (self);
    keccak_function (self->state, self->rounds);

    /* First squeeze */
    self->squeezing = 1;
    keccak_squeeze_internal (self);
    self->valid_bytes = self->rate;
    return 0;
}

KECCAK_API int keccak_squeeze (keccak_state *self, uint8_t *out, size_t length, uint8_t padding)
{
    unsigned valid_bytes;

    if ((NULL == self) || (NULL == out))
        return ERR_NULL;

    if (self->squeezing == 0) {
        int result;

        result = keccak_finish (self, padding);
        if (result)
            return result;
    }

    /* Read once and check (see keccak_absorb) */
    valid_bytes = self->valid_bytes;
    if (valid_bytes == 0 || valid_bytes > self->rate)
        return ERR_STATE;

    while (length > 0) {
        unsigned tc;

        tc = (unsigned)MIN(valid_bytes, length);
        memcpy(out, self->buf + (self->rate - valid_bytes), tc);

        valid_bytes       -= tc;
        out               += tc;
        length            -= tc;

        if (valid_bytes == 0) {
            keccak_function (self->state, self->rounds);
            keccak_squeeze_internal (self);
            valid_bytes = self->rate;
        }
    }

    self->valid_bytes = valid_bytes;
    return 0;
}

KECCAK_API int keccak_digest(keccak_state *state, uint8_t *digest, size_t len, uint8_t padding)
{
    keccak_state tmp;

    if ((NULL==state) || (NULL==digest))
        return ERR_NULL;

    if (2*len != state->capacity)
        return ERR_UNKNOWN;

    tmp = *state;
    return keccak_squeeze(&tmp, digest, len, padding);
}

/*
 * Absorb a whole message and squeeze out_len bytes, in one call,
 * without allocating a state (e.g. SHA-3: capacity 2*out_len,
 * 24 rounds, padding 0x06).
 */
KECCAK_API int keccak_oneshot(const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t out_len,
                              size_t capacity_bytes, uint8_t rounds, uint8_t padding)
{
    keccak_state ks;
    int result;

    if ((NULL == in && in_len > 0) || NULL == out)
        return ERR_NULL;

    result = keccak_check_params(capacity_bytes, rounds);
    if (result)
        return result;

    memset(&ks, 0, sizeof ks);
    keccak_init_state(&ks, capacity_bytes, rounds);

    if (in_len > 0) {
        result = keccak_absorb(&ks, in, in_len);
        if (result)
            return result;
    }
    return keccak_squeeze(&ks, out, out_len, padding);
}

KECCAK_API int keccak_copy(const keccak_state *src, keccak_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    return 0;
}

/**
 * Compute the expensive inner loop of PBKDF2-HMAC, for a hash like SHA-3
 * (whose digest is half the capacity), for one block of output.
 *
 * @inner:      the inner hash of HMAC, after the padded key (one full block)
 * @outer:      the outer hash of HMAC, after the padded key (one full block)
 * @first_hmac: the HMAC of the salt and of the block index (U_1)
 * @result:     the output, U_1 xor U_2 xor ... xor U_iterations
 * @iterations: the iteration count of PBKDF2
 * @digest_size: the size of the digest and of @first_hmac and @result
 * @padding:    the padding byte of the hash (0x06 for SHA-3)
 *
 * Each HMAC takes two permutations, one for the inner hash and one for the
 * outer, as the digest fits in a single block with the padding.
 */
KECCAK_API int keccak_pbkdf2_hmac_assist(const keccak_state *inner, const keccak_state *outer,
                                         const uint8_t *first_hmac,
                                         uint8_t *result,
                                         size_t iterations,
                                         size_t digest_size,
                                         uint8_t padding)
{
    uint64_t s[25], acc[8];
    uint8_t block[KECCAK_F1600_STATE];
    unsigned i, nw, last;
    size_t it;

    if (NULL == inner || NULL == outer || NULL == first_hmac || NULL == result) {
        return ERR_NULL;
    }

    if (iterations == 0) {
        return ERR_NR_ROUNDS;
    }

    if (digest_size == 0 || digest_size > 64 ||
        2*digest_size != inner->capacity || inner->capacity != outer->capacity ||
        inner->rounds != outer->rounds) {
        return ERR_DIGEST_SIZE;
    }

    /** Both hashes must have absorbed exactly one block (the padded HMAC key) **/
    if (inner->valid_bytes != 0 || outer->valid_bytes != 0 ||
        inner->squeezing != 0 || outer->squeezing != 0) {
        return ERR_STATE;
    }

    nw = (unsigned)(digest_size + 1 + 7) / 8;  /* Lanes with the digest and the padding byte */
    last = inner->rate / 8 - 1;                 /* Lane with the final bit of the padding */

    /** block[] holds the last digest, then the padding byte, then zeroes **/
    memset(block, 0, sizeof block);
    memcpy(block, first_hmac, digest_size);
    for (i=0; i<8; i++) {
        acc[i] = LOAD_U64_LITTLE(block + 8*i);
    }

    for (it=1; it<iterations; it++) {
        /* Inner hash */
        block[digest_size] = padding;
        memcpy(s, inner->state, sizeof s);
        for (i=0; i<nw; i++) {
            s[i] ^= LOAD_U64_LITTLE(block + 8*i);
        }
        s[last] ^= 0x8000000000000000ULL;
        keccak_function(s, inner->rounds);
        for (i=0; i<nw; i++) {
            STORE_U64_LITTLE(block + 8*i, s[i]);
        }
        memset(block + digest_size, 0, nw*8 - digest_size);

        /* Outer hash */
        block[digest_size] = padding;
        memcpy(s, outer->state, sizeof s);
        for (i=0; i<nw; i++) {
            s[i] ^= LOAD_U64_LITTLE(block + 8*i);
        }
        s[last] ^= 0x8000000000000000ULL;
        keccak_function(s, outer->rounds);
        for (i=0; i<nw; i++) {
            STORE_U64_LITTLE(block + 8*i, s[i]);
        }
        memset(block + digest_size, 0, nw*8 - digest_size);

        for (i=0; i<8; i++) {
            acc[i] ^= LOAD_U64_LITTLE(block + 8*i);
        }
    }

    for (i=0; i<8; i++) {
        STORE_U64_LITTLE(block + 8*i, acc[i]);
    }
    memcpy(result, block, digest_size);
    return 0;
}

/* Keccak core function */

#define KECCAK_ROUNDS 24

static const uint64_t roundconstants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

/*
 * The Keccak-p[1600, rounds] permutation, for 24 rounds (Keccak-f[1600])
 * or 12 rounds (KangarooTwelve and TurboSHAKE).
 *
 * Lane (x, y) of the state is state[x + 5*y]. In each round, the lanes of
 * one output plane are computed and passed through Chi before the next
 * plane: only 5 intermediate values (b0..b4) are live at a time,
 * instead of 25. With 16 general-purpose registers (x86-64), that saves
 * many spills to the stack. Two rounds are computed per iteration,
 * from a0..a24 into e0..e24 and back, so that no copy is needed.
 */
static void keccak_function (uint64_t *state, unsigned rounds)
{
    unsigned i;

    uint64_t a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12;
    uint64_t a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24;
    uint64_t e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12;
    uint64_t e13, e14, e15, e16, e17, e18, e19, e20, e21, e22, e23, e24;
    uint64_t b0, b1, b2, b3, b4;
    uint64_t c0, c1, c2, c3, c4;
    uint64_t d0, d1, d2, d3, d4;

    a0  = state[0];
    a1  = state[1];
    a2  = state[2];
    a3  = state[3];
    a4  = state[4];
    a5  = state[5];
    a6  = state[6];
    a7  = state[7];
    a8  = state[8];
    a9  = state[9];
    a10 = state[10];
    a11 = state[11];
    a12 = state[12];
    a13 = state[13];
    a14 = state[14];
    a15 = state[15];
    a16 = state[16];
    a17 = state[17];
    a18 = state[18];
    a19 = state[19];
    a20 = state[20];
    a21 = state[21];
    a22 = state[22];
    a23 = state[23];
    a24 = state[24];

    /* 24 rounds, or the last 12 of them (always an even number) */
    for (i = KECCAK_ROUNDS - rounds; i < KECCAK_ROUNDS; i += 2) {
        /* Theta: the parities of the columns */
        c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
        c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
        c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
        c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
        c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
        d0 = c4 ^ ROL64(c1, 1);
        d1 = c0 ^ ROL64(c2, 1);
        d2 = c1 ^ ROL64(c3, 1);
        d3 = c2 ^ ROL64(c4, 1);
        d4 = c3 ^ ROL64(c0, 1);

        /* Theta, Rho and Pi for the lanes of plane 0, then Chi and Iota */
        b0 = a0 ^ d0;
        b1 = ROL64(a6 ^ d1, 44);
        b2 = ROL64(a12 ^ d2, 43);
        b3 = ROL64(a18 ^ d3, 21);
        b4 = ROL64(a24 ^ d4, 14);
        e0 = b0 ^ (~b1 & b2) ^ roundconstants[i];
        e1 = b1 ^ (~b2 & b3);
        e2 = b2 ^ (~b3 & b4);
        e3 = b3 ^ (~b4 & b0);
        e4 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 1, then Chi */
        b0 = ROL64(a3 ^ d3, 28);
        b1 = ROL64(a9 ^ d4, 20);
        b2 = ROL64(a10 ^ d0, 3);
        b3 = ROL64(a16 ^ d1, 45);
        b4 = ROL64(a22 ^ d2, 61);
        e5 = b0 ^ (~b1 & b2);
        e6 = b1 ^ (~b2 & b3);
        e7 = b2 ^ (~b3 & b4);
        e8 = b3 ^ (~b4 & b0);
        e9 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 2, then Chi */
        b0 = ROL64(a1 ^ d1, 1);
        b1 = ROL64(a7 ^ d2, 6);
        b2 = ROL64(a13 ^ d3, 25);
        b3 = ROL64(a19 ^ d4, 8);
        b4 = ROL64(a20 ^ d0, 18);
        e10 = b0 ^ (~b1 & b2);
        e11 = b1 ^ (~b2 & b3);
        e12 = b2 ^ (~b3 & b4);
        e13 = b3 ^ (~b4 & b0);
        e14 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 3, then Chi */
        b0 = ROL64(a4 ^ d4, 27);
        b1 = ROL64(a5 ^ d0, 36);
        b2 = ROL64(a11 ^ d1, 10);
        b3 = ROL64(a17 ^ d2, 15);
        b4 = ROL64(a23 ^ d3, 56);
        e15 = b0 ^ (~b1 & b2);
        e16 = b1 ^ (~b2 & b3);
        e17 = b2 ^ (~b3 & b4);
        e18 = b3 ^ (~b4 & b0);
        e19 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 4, then Chi */
        b0 = ROL64(a2 ^ d2, 62);
        b1 = ROL64(a8 ^ d3, 55);
        b2 = ROL64(a14 ^ d4, 39);
        b3 = ROL64(a15 ^ d0, 41);
        b4 = ROL64(a21 ^ d1, 2);
        e20 = b0 ^ (~b1 & b2);
        e21 = b1 ^ (~b2 & b3);
        e22 = b2 ^ (~b3 & b4);
        e23 = b3 ^ (~b4 & b0);
        e24 = b4 ^ (~b0 & b1);

        /* Theta: the parities of the columns */
        c0 = e0 ^ e5 ^ e10 ^ e15 ^ e20;
        c1 = e1 ^ e6 ^ e11 ^ e16 ^ e21;
        c2 = e2 ^ e7 ^ e12 ^ e17 ^ e22;
        c3 = e3 ^ e8 ^ e13 ^ e18 ^ e23;
        c4 = e4 ^ e9 ^ e14 ^ e19 ^ e24;
        d0 = c4 ^ ROL64(c1, 1);
        d1 = c0 ^ ROL64(c2, 1);
        d2 = c1 ^ ROL64(c3, 1);
        d3 = c2 ^ ROL64(c4, 1);
        d4 = c3 ^ ROL64(c0, 1);

        /* Theta, Rho and Pi for the lanes of plane 0, then Chi and Iota */
        b0 = e0 ^ d0;
        b1 = ROL64(e6 ^ d1, 44);
        b2 = ROL64(e12 ^ d2, 43);
        b3 = ROL64(e18 ^ d3, 21);
        b4 = ROL64(e24 ^ d4, 14);
        a0 = b0 ^ (~b1 & b2) ^ roundconstants[i + 1];
        a1 = b1 ^ (~b2 & b3);
        a2 = b2 ^ (~b3 & b4);
        a3 = b3 ^ (~b4 & b0);
        a4 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 1, then Chi */
        b0 = ROL64(e3 ^ d3, 28);
        b1 = ROL64(e9 ^ d4, 20);
        b2 = ROL64(e10 ^ d0, 3);
        b3 = ROL64(e16 ^ d1, 45);
        b4 = ROL64(e22 ^ d2, 61);
        a5 = b0 ^ (~b1 & b2);
        a6 = b1 ^ (~b2 & b3);
        a7 = b2 ^ (~b3 & b4);
        a8 = b3 ^ (~b4 & b0);
        a9 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 2, then Chi */
        b0 = ROL64(e1 ^ d1, 1);
        b1 = ROL64(e7 ^ d2, 6);
        b2 = ROL64(e13 ^ d3, 25);
        b3 = ROL64(e19 ^ d4, 8);
        b4 = ROL64(e20 ^ d0, 18);
        a10 = b0 ^ (~b1 & b2);
        a11 = b1 ^ (~b2 & b3);
        a12 = b2 ^ (~b3 & b4);
        a13 = b3 ^ (~b4 & b0);
        a14 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 3, then Chi */
        b0 = ROL64(e4 ^ d4, 27);
        b1 = ROL64(e5 ^ d0, 36);
        b2 = ROL64(e11 ^ d1, 10);
        b3 = ROL64(e17 ^ d2, 15);
        b4 = ROL64(e23 ^ d3, 56);
        a15 = b0 ^ (~b1 & b2);
        a16 = b1 ^ (~b2 & b3);
        a17 = b2 ^ (~b3 & b4);
        a18 = b3 ^ (~b4 & b0);
        a19 = b4 ^ (~b0 & b1);

        /* Theta, Rho and Pi for the lanes of plane 4, then Chi */
        b0 = ROL64(e2 ^ d2, 62);
        b1 = ROL64(e8 ^ d3, 55);
        b2 = ROL64(e14 ^ d4, 39);
        b3 = ROL64(e15 ^ d0, 41);
        b4 = ROL64(e21 ^ d1, 2);
        a20 = b0 ^ (~b1 & b2);
        a21 = b1 ^ (~b2 & b3);
        a22 = b2 ^ (~b3 & b4);
        a23 = b3 ^ (~b4 & b0);
        a24 = b4 ^ (~b0 & b1);
    }

    state[0]  = a0;
    state[1]  = a1;
    state[2]  = a2;
    state[3]  = a3;
    state[4]  = a4;
    state[5]  = a5;
    state[6]  = a6;
    state[7]  = a7;
    state[8]  = a8;
    state[9]  = a9;
    state[10] = a10;
    state[11] = a11;
    state[12] = a12;
    state[13] = a13;
    state[14] = a14;
    state[15] = a15;
    state[16] = a16;
    state[17] = a17;
    state[18] = a18;
    state[19] = a19;
    state[20] = a20;
    state[21] = a21;
    state[22] = a22;
    state[23] = a23;
    state[24] = a24;
}


