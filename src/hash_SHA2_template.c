/*
 * An generic implementation of the SHA-2 hash family, this is endian neutral
 * so should work just about anywhere.
 *
 * This code works much like the MD5 code provided by RSA.  You sha_init()
 * a "sha_state" then sha_process() the bytes you want and sha_done() to get
 * the output.
 *
 * Originally written by Tom St Denis -- http://tomstdenis.home.dhs.org
 * Adapted for PyCrypto by Jeethu Rao, Taylor Boon, and others.
 * Turned into a generic template by Lorenz Quack <don@amberfisharts.com>
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
 *
 */

#include "pycrypto_common.h"

FAKE_INIT(MODULE_NAME)

#define FUNC_NAME(pf) _PASTE2(MODULE_NAME, pf)

/* compress one block  */
static void sha_compress(hash_state * hs)
{
    sha2_word_t S[8], W[SCHEDULE_SIZE], T1, T2;
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++)
        S[i] = hs->state[i];

    /* copy the state into W[0..15] */
    for (i = 0; i < 16; i++){
        W[i] = (
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+0]) << (WORD_SIZE_BITS- 8)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+1]) << (WORD_SIZE_BITS-16)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+2]) << (WORD_SIZE_BITS-24)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+3]) << (WORD_SIZE_BITS-32))
#if (WORD_SIZE_BITS == 64)
            |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+4]) << (WORD_SIZE_BITS-40)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+5]) << (WORD_SIZE_BITS-48)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+6]) << (WORD_SIZE_BITS-56)) |
            (((sha2_word_t) hs->buf[(WORD_SIZE*i)+7]))
#endif
            );
    }    

    /* fill W[16..SCHEDULE_SIZE] */
    for (i = 16; i < SCHEDULE_SIZE; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    /* Compress */
    for (i = 0; i < SCHEDULE_SIZE; i++) {
        T1 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        T2 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + T1;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = T1 + T2;
    }

    /* feedback */
    for (i = 0; i < 8; i++)
        hs->state[i] += S[i];
}

/* adds *inc* to the length of the hash_state *hs*
 * return 1 on success
 * return 0 if the length overflows
 */
static int add_length(hash_state *hs, sha2_word_t inc) {
    sha2_word_t overflow_detector;
    overflow_detector = hs->length_lower;
    hs->length_lower += inc;
    if (overflow_detector > hs->length_lower) {
        overflow_detector = hs->length_upper;
        hs->length_upper++;
    }
    return 1;
}

/* init the SHA state */
EXPORT_SYM int FUNC_NAME(_init) (hash_state **shaState)
{
    int i;
    hash_state *hs;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    *shaState = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;

    hs->curlen = hs->length_upper = hs->length_lower = 0;
    for (i = 0; i < 8; ++i)
        hs->state[i] = H[i];
    return 0;
}

EXPORT_SYM int FUNC_NAME(_destroy) (hash_state *shaState)
{
    free(shaState);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_update) (hash_state *hs, const uint8_t *buf, size_t len)
{
    if (NULL == hs || NULL == buf) {
        return ERR_NULL;
    }

    while (len--) {
        /* copy byte */
        hs->buf[hs->curlen++] = *buf++;

        /* is a block full? */
        if (hs->curlen == BLOCK_SIZE) {
            sha_compress(hs);
            add_length(hs, BLOCK_SIZE_BITS);
            hs->curlen = 0;
        }
    }
    return 0;
}

static int sha_finalize(hash_state *hs, uint8_t hash[DIGEST_SIZE])
{
    unsigned i;

    /* increase the length of the message */
    add_length(hs, hs->curlen * 8);

    /* append the '1' bit */
    hs->buf[hs->curlen++] = 0x80;

    /* if the length is currently above LAST_BLOCK_SIZE bytes we append
     * zeros then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (hs->curlen > LAST_BLOCK_SIZE) {
        for (; hs->curlen < BLOCK_SIZE;)
            hs->buf[hs->curlen++] = 0;
        sha_compress(hs);
        hs->curlen = 0;
    }

    /* pad upto LAST_BLOCK_SIZE bytes of zeroes */
    for (; hs->curlen < LAST_BLOCK_SIZE;)
        hs->buf[hs->curlen++] = 0;

    /* append length */
    for (i = 0; i < WORD_SIZE; i++)
        hs->buf[i + LAST_BLOCK_SIZE] = 
            (hs->length_upper >> ((WORD_SIZE - 1 - i) * 8)) & 0xFF;
    for (i = 0; i < WORD_SIZE; i++)
        hs->buf[i + LAST_BLOCK_SIZE + WORD_SIZE] = 
            (hs->length_lower >> ((WORD_SIZE - 1 - i) * 8)) & 0xFF;
    sha_compress(hs);

    /* copy output */
    for (i = 0; i < DIGEST_SIZE; i++)
        hash[i] = (hs->state[i / WORD_SIZE] >> 
                   ((WORD_SIZE - 1 - (i % WORD_SIZE)) * 8)) & 0xFF;
    return 0;
}

EXPORT_SYM int FUNC_NAME(_digest) (const hash_state *shaState, uint8_t digest[DIGEST_SIZE])
{
    hash_state temp;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    temp = *shaState;
    sha_finalize(&temp, digest);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_copy)(const hash_state *src, hash_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    return 0;
}
