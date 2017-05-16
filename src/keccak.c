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

#include "pycrypto_common.h"
#include <string.h>
#include <assert.h>

FAKE_INIT(keccak)

typedef struct
{
    uint64_t state[25];

    /*  The buffer is as long as the state,
     *  but only 'rate' bytes will be used.
     */
    uint8_t  buf[200];

    /*  When absorbing, this is the number of bytes in buf that
     *  are coming from the message and outstanding.
     *  When squeezing, this is the remaining number of bytes
     *  that can be used as digest.
     */
    size_t  valid_bytes;

    /* All values in bytes */
    uint16_t security;
    uint16_t capacity;
    uint16_t rate;

    uint8_t  squeezing;
    uint8_t  padding;
} keccak_state;

#undef ROL64
#define ROL64(x,y) ((((x) << (y)) | (x) >> (64-(y))) & 0xFFFFFFFFFFFFFFFFULL)

static inline int little_endian(void) {
    const int test = 1;
    return *((uint8_t*)&test) == 1;
}

static inline uint64_t load64_le(const uint8_t p[])
{
    union {
        int64_t dw;
        uint8_t b[8];
    } result;

    if (little_endian()) {
        memcpy(&result, p, sizeof result);
    } else {
        result.b[0] = p[7];
        result.b[1] = p[6];
        result.b[2] = p[5];
        result.b[3] = p[4];
        result.b[4] = p[3];
        result.b[5] = p[2];
        result.b[6] = p[1];
        result.b[7] = p[0];
    }

    return result.dw;
}

static inline void store64_le(uint8_t dest[], uint64_t src)
{
    union t {
        int64_t dw;
        uint8_t b[8];
    } *result = (void*) &src;

    if (little_endian()) {
        memcpy(dest, &src, sizeof src);
    } else {
        dest[0] = result->b[7];
        dest[1] = result->b[6];
        dest[2] = result->b[5];
        dest[3] = result->b[4];
        dest[4] = result->b[3];
        dest[5] = result->b[2];
        dest[6] = result->b[1];
        dest[7] = result->b[0];
    }
}


static void keccak_function (uint64_t *state);

static void keccak_absorb_internal (keccak_state *self)
{
    short i,j;
    uint64_t d;
    
    for (i = j = 0; j < self->rate; ++i, j += 8) {
        d = load64_le(self->buf + j);
        self->state[i] ^= d;
    }
}

static void
keccak_squeeze_internal (keccak_state *self)
{
    short i, j;

    for (i = j = 0; j < self->rate; ++i, j += 8) {
        store64_le(self->buf+j, self->state[i]);
    }
}

EXPORT_SYM int keccak_init (keccak_state **state,
                            size_t capacity_bytes,
                            uint8_t padding)
{
    keccak_state *ks;

    if (NULL == state) {
        return ERR_NULL;
    }

    *state = ks = (keccak_state*) calloc(1, sizeof(keccak_state));
    if (NULL == ks)
        return ERR_MEMORY;

    ks->capacity  = capacity_bytes;

    if (ks->capacity >= 200)
        return ERR_DIGEST_SIZE;

    ks->rate      = 200 - ks->capacity;
    
    ks->squeezing = 0;
    ks->padding   = padding;
    
    return 0;
}

EXPORT_SYM int keccak_destroy(keccak_state *state)
{
    free(state);
    return 0;
}

static inline unsigned minAB(unsigned a, unsigned b)
{
    return a<b ? a :b;
}

EXPORT_SYM int keccak_absorb (keccak_state *self,
                              const uint8_t *in,
                              size_t length)
{
    if (NULL==self || NULL==in)
        return ERR_NULL;
    
    if (self->squeezing)
        return ERR_UNKNOWN;
    
    while (length > 0) {
        unsigned bytestocopy;
        
        bytestocopy = minAB(length, self->rate - self->valid_bytes);
        memcpy(self->buf + self->valid_bytes, in, bytestocopy);
      
        self->valid_bytes += bytestocopy;
        in                += bytestocopy;  
        length            -= bytestocopy;

        if (self->valid_bytes == self->rate) {
            keccak_absorb_internal (self);
            keccak_function (self->state);
            self->valid_bytes = 0;
        }
    }

    return 0;
}

static void keccak_finish (keccak_state *self)
{
    assert(self->squeezing == 0);
    assert(self->valid_bytes < self->rate);

    /* Padding */
    memset(self->buf + self->valid_bytes, 0, self->rate - self->valid_bytes);
    self->buf[self->valid_bytes] = self->padding;
    self->buf[self->rate-1] |= 0x80;
    
    /* Final absorb */
    keccak_absorb_internal (self);
    keccak_function (self->state);
    
    /* First squeeze */
    self->squeezing = 1;
    keccak_squeeze_internal (self);
    self->valid_bytes = self->rate;
}

EXPORT_SYM int keccak_squeeze (keccak_state *self, uint8_t *out, size_t length)
{
    if ((NULL == self) || (NULL == out))
        return ERR_NULL;

    if (!self->squeezing) {
        keccak_finish (self);
    }

    assert(self->valid_bytes > 0);
    assert(self->valid_bytes <= self->rate);

    while (length > 0) {
        unsigned bytestocopy;

        bytestocopy = minAB(self->valid_bytes, length);
        memcpy(out, self->buf + (self->rate - self->valid_bytes), bytestocopy);
        
        self->valid_bytes -= bytestocopy;
        out               += bytestocopy;
        length            -= bytestocopy;

        if (self->valid_bytes == 0) {
            keccak_function (self->state);
            keccak_squeeze_internal (self);
            self->valid_bytes = self->rate;
        }
    }

    return 0;
}

EXPORT_SYM int keccak_digest(keccak_state *state, uint8_t *digest, size_t len)
{
    keccak_state tmp;

    if ((NULL==state) || (NULL==digest))
        return ERR_NULL;
    
    if (2*len != state->capacity)
        return ERR_UNKNOWN;
    
    tmp = *state;
    return keccak_squeeze(&tmp, digest, len);
}

/* Keccak core function */

#define KECCAK_ROUNDS 24

#define ROT_01 36
#define ROT_02 3
#define ROT_03 41
#define ROT_04 18
#define ROT_05 1
#define ROT_06 44
#define ROT_07 10
#define ROT_08 45
#define ROT_09 2
#define ROT_10 62
#define ROT_11 6
#define ROT_12 43
#define ROT_13 15
#define ROT_14 61
#define ROT_15 28
#define ROT_16 55
#define ROT_17 25
#define ROT_18 21
#define ROT_19 56
#define ROT_20 27
#define ROT_21 20
#define ROT_22 39
#define ROT_23 8
#define ROT_24 14

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

void keccak_function (uint64_t *state)
{
    short i;
        
    /* Temporary variables to avoid indexing overhead */
    uint64_t a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12;
    uint64_t a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24;
    
    uint64_t b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12;
    uint64_t b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24;
    
    uint64_t c0, c1, c2, c3, c4, d;

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
        
    for (i = 0; i < KECCAK_ROUNDS; ++i) {
        /*
           Uses temporary variables and loop unrolling to
           avoid array indexing and inner loops overhead
        */
        
        /* Prepare column parity for Theta step */
        c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
        c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
        c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
        c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;  
        c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
        
        /* Theta + Rho + Pi steps */
        d   = c4 ^ ROL64(c1, 1);
        b0  = d ^ a0;
        b16 = ROL64(d ^ a5,  ROT_01);       
        b7  = ROL64(d ^ a10, ROT_02);
        b23 = ROL64(d ^ a15, ROT_03);
        b14 = ROL64(d ^ a20, ROT_04);
        
        d   = c0 ^ ROL64(c2, 1);
        b10 = ROL64(d ^ a1,  ROT_05);                       
        b1  = ROL64(d ^ a6,  ROT_06);
        b17 = ROL64(d ^ a11, ROT_07);
        b8  = ROL64(d ^ a16, ROT_08);
        b24 = ROL64(d ^ a21, ROT_09);
        
        d   = c1 ^ ROL64(c3, 1);
        b20 = ROL64(d ^ a2,  ROT_10);
        b11 = ROL64(d ^ a7,  ROT_11);            
        b2  = ROL64(d ^ a12, ROT_12);
        b18 = ROL64(d ^ a17, ROT_13);
        b9  = ROL64(d ^ a22, ROT_14);
        
        d   = c2 ^ ROL64(c4, 1);
        b5  = ROL64(d ^ a3,  ROT_15);  
        b21 = ROL64(d ^ a8,  ROT_16);
        b12 = ROL64(d ^ a13, ROT_17);                      
        b3  = ROL64(d ^ a18, ROT_18);
        b19 = ROL64(d ^ a23, ROT_19);
        
        d   = c3 ^ ROL64(c0, 1);
        b15 = ROL64(d ^ a4,  ROT_20);
        b6  = ROL64(d ^ a9,  ROT_21);
        b22 = ROL64(d ^ a14, ROT_22);
        b13 = ROL64(d ^ a19, ROT_23);
        b4  = ROL64(d ^ a24, ROT_24);

        /* Chi + Iota steps */
        a0  = b0  ^ (~b1  & b2) ^ roundconstants[i];
        a1  = b1  ^ (~b2  & b3);
        a2  = b2  ^ (~b3  & b4);
        a3  = b3  ^ (~b4  & b0);
        a4  = b4  ^ (~b0  & b1);
        
        a5  = b5  ^ (~b6  & b7);
        a6  = b6  ^ (~b7  & b8);
        a7  = b7  ^ (~b8  & b9);
        a8  = b8  ^ (~b9  & b5);
        a9  = b9  ^ (~b5  & b6);
        
        a10 = b10 ^ (~b11 & b12);
        a11 = b11 ^ (~b12 & b13);        
        a12 = b12 ^ (~b13 & b14);
        a13 = b13 ^ (~b14 & b10);
        a14 = b14 ^ (~b10 & b11);
        
        a15 = b15 ^ (~b16 & b17);
        a16 = b16 ^ (~b17 & b18);
        a17 = b17 ^ (~b18 & b19);
        a18 = b18 ^ (~b19 & b15);
        a19 = b19 ^ (~b15 & b16);
        
        a20 = b20 ^ (~b21 & b22);
        a21 = b21 ^ (~b22 & b23);
        a22 = b22 ^ (~b23 & b24);
        a23 = b23 ^ (~b24 & b20);
        a24 = b24 ^ (~b20 & b21);
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


