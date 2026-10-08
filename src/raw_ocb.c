/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

FAKE_INIT(raw_ocb)

#include "block_base.h"

#define BLOCK_SIZE 16

typedef uint8_t DataBlock[BLOCK_SIZE];

typedef struct {
    BlockBase   *cipher;

    DataBlock   L_star;
    DataBlock   L_dollar;
    DataBlock   L[65];  /** 0..64 **/

    /**
     * Associated data, processed so far in whole blocks
     * (indexed from 1, as in RFC 7253):
     * - counter_A: the index of the next block to process, which is
     *   one more than the number of blocks processed so far.
     * - offset_A: the offset of the last block processed (block counter_A-1),
     *   or zero if there is none. Block i uses the offset of block i-1,
     *   XORed with L[ntz(i)].
     * - sum: the XOR of the encrypted blocks, which is HASH(K,A) once
     *   all associated data has been processed.
     * The last piece of associated data (shorter than a block) does not
     * change counter_A and offset_A: it uses offset_A XORed with L_*.
     */
    uint64_t    counter_A;
    DataBlock   offset_A;
    DataBlock   sum;

    /**
     * Plaintext/ciphertext, processed so far in whole blocks
     * (indexed from 1, as in RFC 7253):
     * - counter_P: the index of the next block to process, which is
     *   one more than the number of blocks processed so far.
     * - offset_P: the offset of the last block processed (block counter_P-1),
     *   or Offset_0 (computed from the nonce) if there is none. Block i uses
     *   the offset of block i-1, XORed with L[ntz(i)].
     * - checksum: the XOR of the plaintext blocks.
     * After the last piece of the message (shorter than a block),
     * offset_P is Offset_* (offset_P XORed with L_*), and the piece,
     * padded, is in checksum. counter_P does not change.
     */
    uint64_t    counter_P;
    DataBlock   offset_P;
    DataBlock   checksum;
} OcbModeState;

static void double_L(DataBlock *out, DataBlock *in)
{
    unsigned carry;
    int i;

    carry = 0;
    for (i=BLOCK_SIZE-1; i>=0; i--) {
        unsigned t;

        t = ((unsigned)(*in)[i] << 1) | carry;
        carry = t >> 8;
        (*out)[i] = (uint8_t)t;
    }
    carry |= 0x100;
    carry |= carry << 1;
    carry |= carry << 2;
    carry |= carry << 4;
    (*out)[BLOCK_SIZE-1] = (uint8_t)((*out)[BLOCK_SIZE-1] ^ (carry & 0x87));
}

static unsigned ntz(uint64_t counter)
{
    unsigned i;
    for (i=0; i<65; i++) {
        if (counter & 1)
            return i;
        counter >>= 1;
    }
    return 64;
}

/** Blocks are processed in batches of NR_BLOCKS, with one call to the cipher **/
#define NR_BLOCKS 8

static inline uint64_t load64(const uint8_t *p)
{
    uint64_t w;

    memcpy(&w, p, 8);
    return w;
}

static inline void store64(uint8_t *p, uint64_t w)
{
    memcpy(p, &w, 8);
}

/**
 * Turn offset from Offset_from into Offset_to (from and to are block
 * indices), without going through the blocks in between.
 *
 * 1. RFC 7253 defines Offset_i = Offset_{i-1} ^ L[ntz(i)]. Repeated,
 *    it gives Offset_i = Offset_0 ^ S(i), with
 *    S(i) = L[ntz(1)] ^ L[ntz(2)] ^ ... ^ L[ntz(i)].
 *
 * 2. An L[k] that appears an even number of times in S(i) cancels out:
 *    S(i) is the XOR of the L[k] that appear an odd number of times.
 *    Remember that k is always a small number, between 0 and 64.
 *
 * 3. Which L[k] appear an odd number of times in S(i)?
 *    ntz(j) = k when j ends, in binary, with a 1 followed by exactly
 *    k zeros: 1, 3, 5... for k = 0; 2, 6, 10... for k = 1; 4, 12... for k = 2.
 *    Among 1..i, let q = i >> k: the multiples of 2^k are 2^k*1 .. 2^k*q,
 *    and those with an odd multiplier (1, 3, 5... up to q) end with
 *    exactly k zeros. There are ceil(q/2) of them, an odd number
 *    if and only if q ends with 01 or 10 in binary. These two bits of q
 *    are bits k and k+1 of i: they differ when bit k of i ^ (i >> 1)
 *    (the Gray code of i) is set.
 *    So, S(i) is the XOR of the L[k] selected by the bits of the Gray
 *    code of i. For instance, with i = 6 (0b110):
 *      k = 0: j = 1, 3, 5   (3 times, odd)   bits 0 and 1 of i differ
 *      k = 1: j = 2, 6      (2 times, even)  bits 1 and 2 of i are equal
 *      k = 2: j = 4         (1 time, odd)    bits 2 and 3 of i differ
 *    so S(6) = L[0] ^ L[2], and the Gray code of 6 is 6 ^ 3 = 0b101.
 *
 * 4. Offset_to = Offset_from ^ S(from) ^ S(to), since the terms common
 *    to S(from) and S(to) cancel out: the L[k] to add are selected by the
 *    XOR of the two Gray codes.
 *    For instance, from block 2 to block 6: 0b011 ^ 0b101 = 0b110,
 *    so L[1] ^ L[2] (directly: L[0] ^ L[2] ^ L[0] ^ L[1] for blocks 3..6).
 *
 * It takes at most 64 XORs of L[k], however far apart the blocks are.
 */
static void move_offset(const OcbModeState *state, DataBlock offset, uint64_t from, uint64_t to)
{
    uint64_t bits;
    unsigned i, k;

    bits = (from ^ (from >> 1)) ^ (to ^ (to >> 1));
    for (k=0; bits != 0; k++, bits >>= 1) {
        if (bits & 1) {
            for (i=0; i<BLOCK_SIZE; i++)
                offset[i] ^= state->L[k][i];
        }
    }
}

/**
 * Check that the block index does not wrap around to 0 when n_blocks
 * blocks are processed from block index first: the index of the block
 * after them must still fit into 64 bits.
 */
static int check_no_wrap(uint64_t first, uint64_t n_blocks)
{
    if (n_blocks > UINT64_MAX - first)
        return ERR_MAX_DATA;
    return 0;
}

enum OcbDirection { OCB_ENCRYPT, OCB_DECRYPT };

/**
 * Encrypt or decrypt n_blocks full blocks, the first one being block
 * index first. On entry, offset is Offset_{first-1}; on exit, it is
 * the offset of the last block. The plaintext blocks are XORed into checksum.
 * in and out can be the same buffer.
 */
static int transcrypt_blocks(const OcbModeState *state,
                             enum OcbDirection direction,
                             const uint8_t *in,
                             uint8_t *out,
                             size_t n_blocks,
                             uint64_t first,
                             DataBlock offset,
                             DataBlock checksum)
{
    CipherOperation process;
    uint8_t pre[NR_BLOCKS*BLOCK_SIZE];
    uint8_t offsets[NR_BLOCKS*BLOCK_SIZE];
    uint64_t offset_lo, offset_hi, checksum_lo, checksum_hi;
    int result = 0;

    process = OCB_ENCRYPT==direction ? state->cipher->encrypt : state->cipher->decrypt;

    offset_lo = load64(offset);
    offset_hi = load64(offset + 8);
    checksum_lo = load64(checksum);
    checksum_hi = load64(checksum + 8);

    while (n_blocks > 0) {
        size_t n, len, j;

        n = MIN(n_blocks, NR_BLOCKS);
        len = n * BLOCK_SIZE;

        /** Read all of in[] before out[] is written (they can overlap) **/
        for (j=0; j<len; j+=BLOCK_SIZE) {
            const uint8_t *l;
            uint64_t in_lo, in_hi;

            l = state->L[ntz(first + j/BLOCK_SIZE)];
            offset_lo ^= load64(l);
            offset_hi ^= load64(l + 8);
            store64(offsets + j, offset_lo);
            store64(offsets + j + 8, offset_hi);

            in_lo = load64(in + j);
            in_hi = load64(in + j + 8);
            store64(pre + j, in_lo ^ offset_lo);
            store64(pre + j + 8, in_hi ^ offset_hi);
            if (OCB_ENCRYPT==direction) {
                checksum_lo ^= in_lo;
                checksum_hi ^= in_hi;
            }
        }

        result = process(state->cipher, pre, out, len);
        if (result)
            break;

        for (j=0; j<len; j+=BLOCK_SIZE) {
            uint64_t out_lo, out_hi;

            out_lo = load64(out + j) ^ load64(offsets + j);
            out_hi = load64(out + j + 8) ^ load64(offsets + j + 8);
            store64(out + j, out_lo);
            store64(out + j + 8, out_hi);
            if (OCB_DECRYPT==direction) {
                checksum_lo ^= out_lo;
                checksum_hi ^= out_hi;
            }
        }

        first += n;
        n_blocks -= n;
        in += len;
        out += len;
    }

    store64(offset, offset_lo);
    store64(offset + 8, offset_hi);
    store64(checksum, checksum_lo);
    store64(checksum + 8, checksum_hi);
    return result;
}

/**
 * Process n_blocks full blocks of associated data, the first one being
 * block index first. On entry, offset is Offset_{first-1}; on exit, it is
 * the offset of the last block. The encrypted blocks are XORed into sum.
 */
static int hash_blocks(const OcbModeState *state,
                       const uint8_t *in,
                       size_t n_blocks,
                       uint64_t first,
                       DataBlock offset,
                       DataBlock sum)
{
    uint8_t pre[NR_BLOCKS*BLOCK_SIZE];
    uint8_t ct[NR_BLOCKS*BLOCK_SIZE];
    uint64_t offset_lo, offset_hi, sum_lo, sum_hi;
    int result = 0;

    offset_lo = load64(offset);
    offset_hi = load64(offset + 8);
    sum_lo = load64(sum);
    sum_hi = load64(sum + 8);

    while (n_blocks > 0) {
        size_t n, len, j;

        n = MIN(n_blocks, NR_BLOCKS);
        len = n * BLOCK_SIZE;

        for (j=0; j<len; j+=BLOCK_SIZE) {
            const uint8_t *l;

            l = state->L[ntz(first + j/BLOCK_SIZE)];
            offset_lo ^= load64(l);
            offset_hi ^= load64(l + 8);
            store64(pre + j, load64(in + j) ^ offset_lo);
            store64(pre + j + 8, load64(in + j + 8) ^ offset_hi);
        }

        result = state->cipher->encrypt(state->cipher, pre, ct, len);
        if (result)
            break;

        for (j=0; j<len; j+=BLOCK_SIZE) {
            sum_lo ^= load64(ct + j);
            sum_hi ^= load64(ct + j + 8);
        }

        first += n;
        n_blocks -= n;
        in += len;
    }

    store64(offset, offset_lo);
    store64(offset + 8, offset_hi);
    store64(sum, sum_lo);
    store64(sum + 8, sum_hi);
    return result;
}

/**
 * Encrypt or decrypt the last piece, of in_len bytes (1..15).
 * On entry, offset is the offset of the last full block; on exit, it is
 * Offset_* (offset ^ L_*). The piece, padded, is XORed into checksum.
 */
static int transcrypt_tail(const OcbModeState *state,
                           enum OcbDirection direction,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len,
                           DataBlock offset,
                           DataBlock checksum)
{
    DataBlock pad;
    unsigned i;
    int result;

    for (i=0; i<BLOCK_SIZE; i++)
        offset[i] ^= state->L_star[i];

    result = state->cipher->encrypt(state->cipher, offset, pad, BLOCK_SIZE);
    if (result)
        return result;

    for (i=0; i<in_len; i++) {
        uint8_t in_byte = in[i];

        out[i] = in_byte ^ pad[i];
        checksum[i] ^= OCB_ENCRYPT==direction ? in_byte : out[i];
    }
    checksum[in_len] ^= 0x80;

    return 0;
}

/**
 * Compute Offset_0 from the nonce (RFC 7253, section 4.2).
 *
 * The nonce is formatted into a block, with the tag length (in bits, modulo 128)
 * in the top 7 bits, then zeroes, a single 1 bit, and the nonce itself.
 * Ktop is the encryption of that block, with the bottom 6 bits cleared.
 * Stretch is Ktop || (Ktop[0..63] xor Ktop[8..71]), 192 bits.
 * Offset_0 is made of the 128 bits of Stretch that start at bit "bottom"
 * (the 6 bits cleared before, counting from the most significant bit).
 */
static int compute_offset_0(const OcbModeState *state,
                            const uint8_t *nonce,
                            size_t nonce_len,
                            size_t tag_len,
                            DataBlock offset_0)
{
    DataBlock formatted;
    uint8_t stretch[BLOCK_SIZE + 8];
    unsigned bottom, byte_shift, bit_shift, i;
    int result;

    memset(formatted, 0, BLOCK_SIZE);
    formatted[0] = (uint8_t)(((tag_len * 8) % 128) << 1);
    formatted[BLOCK_SIZE - 1 - nonce_len] |= 1;
    memcpy(formatted + BLOCK_SIZE - nonce_len, nonce, nonce_len);

    bottom = formatted[BLOCK_SIZE - 1] & 0x3F;
    formatted[BLOCK_SIZE - 1] &= 0xC0;

    result = state->cipher->encrypt(state->cipher, formatted, stretch, BLOCK_SIZE);
    if (result)
        return result;
    for (i=0; i<8; i++)
        stretch[BLOCK_SIZE + i] = stretch[i] ^ stretch[i + 1];

    byte_shift = bottom / 8;
    bit_shift = bottom % 8;
    for (i=0; i<BLOCK_SIZE; i++) {
        unsigned two_bytes;

        /** byte_shift + i + 1 is at most 7 + 15 + 1, within stretch **/
        two_bytes = (unsigned)stretch[byte_shift + i] << 8 | stretch[byte_shift + i + 1];
        offset_0[i] = (uint8_t)(two_bytes >> (8 - bit_shift));
    }

    return 0;
}

/**
 * Create the state for an OCB encryption or decryption.
 *
 * @cipher     The block cipher (with 16 byte blocks), which the state then owns.
 * @nonce      The nonce (1 to 15 bytes).
 * @tag_len    The length of the tag, in bytes (1 to 16).
 * @pState     Where to store the new state.
 */
EXPORT_SYM int OCB_start_operation(BlockBase *cipher,
                                   const uint8_t *nonce,
                                   size_t nonce_len,
                                   size_t tag_len,
                                   OcbModeState **pState)
{
    OcbModeState *state;
    DataBlock zero;
    int result;
    unsigned i;

    if ((NULL == cipher) || (NULL == nonce) || (NULL == pState)) {
        return ERR_NULL;
    }

    if (BLOCK_SIZE != cipher->block_len) {
        return ERR_BLOCK_SIZE;
    }

    if ((nonce_len == 0) || (nonce_len >= BLOCK_SIZE)) {
        return ERR_NONCE_SIZE;
    }

    if ((tag_len == 0) || (tag_len > BLOCK_SIZE)) {
        return ERR_TAG_SIZE;
    }

    state = calloc(1, sizeof(OcbModeState));
    if (NULL == state) {
        return ERR_MEMORY;
    }

    state->cipher = cipher;

    memset(zero, 0, BLOCK_SIZE);
    result = state->cipher->encrypt(state->cipher, zero, state->L_star, BLOCK_SIZE);
    if (result)
        goto error;

    double_L(&state->L_dollar, &state->L_star);
    double_L(&state->L[0], &state->L_dollar);
    for (i=1; i<=64; i++)
        double_L(&state->L[i], &state->L[i-1]);

    result = compute_offset_0(state, nonce, nonce_len, tag_len, state->offset_P);
    if (result)
        goto error;

    state->counter_A = state->counter_P = 1;

    *pState = state;
    return 0;

error:
    /** The caller still owns the cipher **/
    free(state);
    return result;
}

/**
 * Encrypt or decrypt the data_len bytes at offset in in[] into the same
 * offset in out[], as if all data before offset had been processed already.
 * offset must be a multiple of 16 bytes. If data_len is not, the range
 * ends with the last piece of the message (shorter than a block),
 * like with OCB_encrypt() and OCB_decrypt().
 * The state is not changed: the checksum of the range goes into checksum[].
 *
 * Several threads can call it at the same time on the same state,
 * for instance each one on a different range of the same buffers,
 * as long as no other function changes the state in the meantime.
 * Afterwards, OCB_skip() moves the state past all the ranges.
 */
static int transcrypt_at(const OcbModeState *state,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t offset,
                         size_t data_len,
                         uint8_t checksum[BLOCK_SIZE],
                         enum OcbDirection direction)
{
    DataBlock offset_P;
    uint64_t first;
    size_t whole_len;
    int result;

    if ((NULL == state) || (NULL == in) || (NULL == out) || (NULL == checksum))
        return ERR_NULL;

    if (offset + data_len < offset)
        return ERR_MAX_DATA;

    if (offset % BLOCK_SIZE)
        return ERR_NOT_ENOUGH_DATA;

    /** The blocks before the range, and the blocks of the range **/
    whole_len = data_len - data_len % BLOCK_SIZE;
    result = check_no_wrap(state->counter_P, (offset + whole_len) / BLOCK_SIZE);
    if (result)
        return result;
    first = state->counter_P + offset / BLOCK_SIZE;

    memset(checksum, 0, BLOCK_SIZE);
    memcpy(offset_P, state->offset_P, BLOCK_SIZE);
    /** Like state->offset_P, the offset of the block before the first one to process **/
    move_offset(state, offset_P, state->counter_P - 1, first - 1);

    in += offset;
    out += offset;
    result = transcrypt_blocks(state, direction, in, out, whole_len / BLOCK_SIZE, first, offset_P, checksum);
    if (result)
        return result;

    if (data_len > whole_len)
        return transcrypt_tail(state, direction, in + whole_len, out + whole_len,
                               data_len - whole_len, offset_P, checksum);

    return 0;
}

EXPORT_SYM int OCB_encrypt_at(const OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t offset,
                              size_t data_len,
                              uint8_t checksum[BLOCK_SIZE])
{
    return transcrypt_at(state, in, out, offset, data_len, checksum, OCB_ENCRYPT);
}

EXPORT_SYM int OCB_decrypt_at(const OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t offset,
                              size_t data_len,
                              uint8_t checksum[BLOCK_SIZE])
{
    return transcrypt_at(state, in, out, offset, data_len, checksum, OCB_DECRYPT);
}

/**
 * Move the state data_len bytes forward in the plaintext/ciphertext,
 * as if OCB_encrypt() or OCB_decrypt() had processed them: if data_len is
 * not a multiple of 16, they end with the last piece of the message.
 * checksum[] is the checksum of those bytes.
 * The caller has checked that the counter does not wrap around.
 */
static void advance(OcbModeState *state, size_t data_len, const uint8_t checksum[BLOCK_SIZE])
{
    uint64_t last;
    unsigned i;

    last = state->counter_P - 1;
    state->counter_P += data_len / BLOCK_SIZE;
    move_offset(state, state->offset_P, last, state->counter_P - 1);

    /** The last piece uses Offset_* (see transcrypt_tail()) **/
    if (data_len % BLOCK_SIZE) {
        for (i=0; i<BLOCK_SIZE; i++)
            state->offset_P[i] ^= state->L_star[i];
    }

    for (i=0; i<BLOCK_SIZE; i++)
        state->checksum[i] ^= checksum[i];
}

/**
 * Like advance(), after OCB_encrypt_at() or OCB_decrypt_at() processed
 * the data in several ranges: checksum[] is the XOR of the checksums
 * of all ranges.
 */
EXPORT_SYM int OCB_skip(OcbModeState *state, size_t data_len, const uint8_t checksum[BLOCK_SIZE])
{
    int result;

    if ((NULL == state) || (NULL == checksum))
        return ERR_NULL;

    result = check_no_wrap(state->counter_P, data_len / BLOCK_SIZE);
    if (result)
        return result;

    advance(state, data_len, checksum);
    return 0;
}

/**
 * Encrypt or decrypt in_len bytes. If in_len is not a multiple of 16,
 * they end with the last piece of the message.
 * The state changes only if all data is processed successfully.
 */
static int transcrypt(OcbModeState *state,
                      const uint8_t *in,
                      uint8_t *out,
                      size_t in_len,
                      enum OcbDirection direction)
{
    DataBlock checksum;
    int result;

    /** It checks the parameters, including that the counter does not wrap around **/
    result = transcrypt_at(state, in, out, 0, in_len, checksum, direction);
    if (result)
        return result;

    advance(state, in_len, checksum);
    return 0;
}

/**
 * Encrypt the next piece of plaintext.
 *
 * @state   The OCB state.
 * @in      The plaintext.
 * @out     The buffer for the ciphertext, as long as the plaintext.
 *          It can be the same buffer as in.
 * @in_len  The length of the plaintext, in bytes. It must be a multiple
 *          of 16, unless this is the last piece of the message.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_encrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return transcrypt(state, in, out, in_len, OCB_ENCRYPT);
}

/**
 * Decrypt the next piece of ciphertext.
 *
 * @state   The OCB state.
 * @in      The ciphertext.
 * @out     The buffer for the plaintext, as long as the ciphertext.
 *          It can be the same buffer as in.
 * @in_len  The length of the ciphertext, in bytes. It must be a multiple
 *          of 16, unless this is the last piece of the message.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_decrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return transcrypt(state, in, out, in_len, OCB_DECRYPT);
}

/**
 * Process the next piece of associated data.
 *
 * @state   The OCB state.
 * @in      The associated data.
 * @in_len  The length of the associated data, in bytes. It must be
 *          a multiple of 16, unless this is the last piece.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_update(OcbModeState *state,
                          const uint8_t *in,
                          size_t in_len)
{
    int result;
    unsigned i;
    size_t n_blocks;
    DataBlock pt;
    DataBlock ct;

    if ((NULL == state) || (NULL == in))
        return ERR_NULL;

    /** Process nothing if the counter would wrap around **/
    n_blocks = in_len / BLOCK_SIZE;
    result = check_no_wrap(state->counter_A, n_blocks);
    if (result)
        return result;

    result = hash_blocks(state, in, n_blocks, state->counter_A, state->offset_A, state->sum);
    if (result)
        return result;
    state->counter_A += n_blocks;

    in += n_blocks * BLOCK_SIZE;
    in_len -= n_blocks * BLOCK_SIZE;

    /** Process last piece (if any) **/
    if (in_len>0) {
        memset(pt, 0, sizeof pt);
        memcpy(pt, in, in_len);
        pt[in_len] = 0x80;

        for (i=0; i<BLOCK_SIZE; i++)
            pt[i] ^= state->offset_A[i] ^ state->L_star[i];

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];
    }

    return 0;
}

/**
 * Compute the tag, after all associated data and plaintext/ciphertext.
 *
 * @state   The OCB state.
 * @tag     The buffer for the tag.
 * @tag_len The length of the buffer: it must be 16 (the caller truncates
 *          the tag, if it is shorter).
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_digest(OcbModeState *state,
                          uint8_t *tag,
                          size_t tag_len)
{
    DataBlock pt;
    unsigned i;
    int result;

    if ((NULL == state) || (NULL == tag))
        return ERR_NULL;

    if (BLOCK_SIZE != tag_len)
        return ERR_TAG_SIZE;

    for (i=0; i<BLOCK_SIZE; i++)
        pt[i] = state->checksum[i] ^ state->offset_P[i] ^ state->L_dollar[i];

    result = state->cipher->encrypt(state->cipher, pt, tag, BLOCK_SIZE);
    if (result)
        return result;

    /** state->sum is HASH(K, A) **/
    for (i=0; i<BLOCK_SIZE; i++)
        tag[i] ^= state->sum[i];

    return 0;
}

/**
 * Free the state, and the block cipher that it owns.
 */
EXPORT_SYM int OCB_stop_operation(OcbModeState *state)
{
    if (NULL == state)
        return ERR_NULL;
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
