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
#include "keccak.h"
#include <string.h>

#define USE_COMPLEMENT_LANES_OPTIMIZATION
/*
    The lane complementing optimization is described in
    ``Keccak implementation overview'' ver. 3.2 sect. 2.2
    <http://keccak.noekeon.org/Keccak-implementation-3.2.pdf>
    
    The number of NOT operations in the Chi step can be reduced
    by representing certain lanes by their complement.
*/

#ifdef KECCAK_USE_BIT_INTERLEAVING
/*
    Use bit interleaving when compiling at 32 bit.
    
    The bit interleaving technique is described in
    ``Keccak implementation overview'' ver. 3.2 sect. 2.1
    <http://keccak.noekeon.org/Keccak-implementation-3.2.pdf>
    
    A 64-bit lane is coded as two 32-bit words, one containing
    the lane bits in even position and the other those in odd
    position. This permits to implement rotations in Rho and Pi
    steps with 32-bit rotations.
*/


/*
    Some code from the Keccak reference implementation
    <http://keccak.noekeon.org/files.html>
*/

#ifdef ENDIAN_LITTLE

static void
keccak_absorb_internal (keccak_state *self)
{
    short i;
    const uint32_t *pI = (const uint32_t *)self->buf;
    uint32_t *pS = self->state;
    uint32_t t, x0, x1;
    
    /* Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
    for (i = 0; i < self->rate; i += 8) {
        x0 = *(pI++);
        t = (x0 ^ (x0 >> 1)) & 0x22222222UL; x0 ^= t ^ (t <<  1);
        t = (x0 ^ (x0 >> 2)) & 0x0C0C0C0CUL; x0 ^= t ^ (t <<  2);
        t = (x0 ^ (x0 >> 4)) & 0x00F000F0UL; x0 ^= t ^ (t <<  4);
        t = (x0 ^ (x0 >> 8)) & 0x0000FF00UL; x0 ^= t ^ (t <<  8);
        
        x1 = *(pI++);
        t = (x1 ^ (x1 >> 1)) & 0x22222222UL; x1 ^= t ^ (t <<  1);
        t = (x1 ^ (x1 >> 2)) & 0x0C0C0C0CUL; x1 ^= t ^ (t <<  2);
        t = (x1 ^ (x1 >> 4)) & 0x00F000F0UL; x1 ^= t ^ (t <<  4);
        t = (x1 ^ (x1 >> 8)) & 0x0000FF00UL; x1 ^= t ^ (t <<  8);
        
        *(pS++) ^= (x0 >> 16) | (x1 & 0xFFFF0000);
        *(pS++) ^= (uint16_t)x0 | (x1 << 16);
    }
}

#else
/* ENDIAN_BIG */ 

/* Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
static uint64_t
toInterleaving (uint64_t x) 
{
   uint64_t t;

   t = (x ^ (x >>  1)) & 0x2222222222222222ULL; x ^= t ^ (t <<  1);
   t = (x ^ (x >>  2)) & 0x0C0C0C0C0C0C0C0CULL; x ^= t ^ (t <<  2);
   t = (x ^ (x >>  4)) & 0x00F000F000F000F0ULL; x ^= t ^ (t <<  4);
   t = (x ^ (x >>  8)) & 0x0000FF000000FF00ULL; x ^= t ^ (t <<  8);
   t = (x ^ (x >> 16)) & 0x00000000FFFF0000ULL; x ^= t ^ (t << 16);

   return x;
}

static void
keccak_absorb_internal (keccak_state *self)
{
    short i,j;
    uint64_t sourceWord, evenAndOddWord;
    
    for (i = j = 0; j < self->rate; i += 2, j += 8) {
        LOAD64L(sourceWord, self->buf + j);
        evenAndOddWord = toInterleaving (sourceWord);
        self->state[i+1] ^= (uint32_t)evenAndOddWord;
        self->state[i]   ^= (uint32_t)(evenAndOddWord >> 32);
    }
}
#endif /* Endianness */

/* Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
static uint64_t
fromInterleaving (uint64_t x)
{
   uint64_t t;

   t = (x ^ (x >> 16)) & 0x00000000FFFF0000ULL; x ^= t ^ (t << 16);
   t = (x ^ (x >>  8)) & 0x0000FF000000FF00ULL; x ^= t ^ (t <<  8);
   t = (x ^ (x >>  4)) & 0x00F000F000F000F0ULL; x ^= t ^ (t <<  4);
   t = (x ^ (x >>  2)) & 0x0C0C0C0C0C0C0C0CULL; x ^= t ^ (t <<  2);
   t = (x ^ (x >>  1)) & 0x2222222222222222ULL; x ^= t ^ (t <<  1);

   return x;
}

#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
static short complemented_lanes[6] = {2, 4, 16, 24, 34, 40};
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */

#define setInterleavedWordsInto8bytes(dest, even, odd)  \
    { \
        destWord = fromInterleaving((uint64_t)even ^ ((uint64_t)odd << 32)); \
        STORE64L(destWord, dest); \
    }

static void
keccak_squeeze_internal (keccak_state *self)
{
    short i, j, x = 0;
    uint64_t destWord;

    for (i = j = 0; j < self->rate; i += 2, j += 8) {
#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
        if (i == complemented_lanes[x]) {
            setInterleavedWordsInto8bytes (self->buf + j, ~self->state[i+1], ~self->state[i]);
            ++x;
        } else {
            setInterleavedWordsInto8bytes (self->buf + j, self->state[i+1], self->state[i]);
        }
#else
        setInterleavedWordsInto8bytes (self->buf + j, self->state[i+1], self->state[i]);
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */
    }
}

#else /* Use 64bit instructions */

#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
static short complemented_lanes[6] = {1, 2, 8, 12, 17, 20};
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */

static void
keccak_absorb_internal (keccak_state *self)
{
    short i,j;
    uint64_t d;
    
    for (i = j = 0; j < self->rate; ++i, j += 8) {
        LOAD64L(d, self->buf + j);
        self->state[i] ^= d;
    }
}

static void
keccak_squeeze_internal (keccak_state *self)
{
    short i, j, x = 0;

    for (i = j = 0; j < self->rate; ++i, j += 8) {
#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
        if (i == complemented_lanes[x]) {
            STORE64L(~self->state[i], self->buf + j);
            ++x;
        } else {
            STORE64L(self->state[i], self->buf + j);
        }
#else
        STORE64L(self->state[i], self->buf + j);
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */
    }
}

#endif /* KECCAK_USE_BIT_INTERLEAVING */

keccak_result
keccak_init (keccak_state *self, unsigned int param, keccak_init_param initby)
{
    uint16_t security, capacity, rate;

    memset (self, 0, sizeof(keccak_state));
    
#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
#ifdef KECCAK_USE_BIT_INTERLEAVING
    self->state[2]  = 0xFFFFFFFFUL;
    self->state[3]  = 0xFFFFFFFFUL;
    self->state[4]  = 0xFFFFFFFFUL;
    self->state[5]  = 0xFFFFFFFFUL;
    self->state[16] = 0xFFFFFFFFUL;
    self->state[17] = 0xFFFFFFFFUL;
    self->state[24] = 0xFFFFFFFFUL;
    self->state[25] = 0xFFFFFFFFUL;
    self->state[34] = 0xFFFFFFFFUL;
    self->state[35] = 0xFFFFFFFFUL;
    self->state[40] = 0xFFFFFFFFUL;
    self->state[41] = 0xFFFFFFFFUL;
#else
    self->state[1]  = 0xFFFFFFFFFFFFFFFFULL;
    self->state[2]  = 0xFFFFFFFFFFFFFFFFULL;
    self->state[8]  = 0xFFFFFFFFFFFFFFFFULL;
    self->state[12] = 0xFFFFFFFFFFFFFFFFULL;
    self->state[17] = 0xFFFFFFFFFFFFFFFFULL;
    self->state[20] = 0xFFFFFFFFFFFFFFFFULL;
#endif /* KECCAK_USE_BIT_INTERLEAVING */
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */

    self->bufptr    = self->buf;
    
    switch (initby) {
        case KECCAK_INIT_SECURITY:
            security = param;
            capacity = 2 * security;
            rate     = 200 - capacity;
            break;
        case KECCAK_INIT_RATE:
            rate     = param;
            capacity = 200 - rate;
            security = capacity/2;
            break;
        default:
            return KECCAK_ERR_UNKNOWNPARAM;
    }
    
    if (rate + capacity != 200)
        return KECCAK_ERR_INVALIDPARAM;
    if ((rate <= 0) || (rate >= 200) || ((rate % 8) != 0))
        return KECCAK_ERR_INVALIDPARAM;
        
    self->security  = security;
    self->capacity  = capacity;
    self->rate      = rate;
    self->bufend    = self->buf + rate - 1;
    self->squeezing = 0;
    
    return KECCAK_OK;
}

keccak_result
keccak_absorb (keccak_state *self, unsigned char *buffer, int length)
{
    int bytestocopy;
    
    if (self->squeezing)
        return KECCAK_ERR_CANTABSORB;
    
    while (length > (self->bufend - self->bufptr)) {
        bytestocopy = (int)(self->bufend - self->bufptr + 1);
        memcpy (self->bufptr, buffer, bytestocopy);
        keccak_absorb_internal (self);
        keccak_function (self->state);
        self->bufptr = self->buf;
        buffer += bytestocopy;
        length -= bytestocopy;
    }
    memcpy (self->bufptr, buffer, length);
    self->bufptr += length;
    
    return KECCAK_OK;
}

keccak_result
keccak_finish (keccak_state *self)
{
    /* Padding */
    *(self->bufptr++) = 0x06U;
    if (self->bufend >= self->bufptr) {
        memset (self->bufptr, 0, self->bufend - self->bufptr + 1);
    }
    *(self->bufend) |= 0x80U;
    
    self->bufptr = self->buf;
    self->squeezing = 1;
    
    /* Final absord-permutation-squeeze */
    keccak_absorb_internal (self);
    keccak_function (self->state);
    keccak_squeeze_internal (self);
    
    return KECCAK_OK;
}

keccak_result
keccak_copy (keccak_state *source, keccak_state *dest)
{
#ifdef KECCAK_USE_BIT_INTERLEAVING
    memcpy (dest->state, source->state, 50 * sizeof(uint32_t));
#else
    memcpy (dest->state, source->state, 25 * sizeof(uint64_t));
#endif
    memcpy (dest->buf, source->buf, source->rate);
    dest->bufptr = dest->buf + (source->bufptr - source->buf);
    dest->bufend = dest->buf + source->rate - 1;
    dest->security  = source->security;
    dest->capacity  = source->capacity;
    dest->rate      = source->rate;
    dest->squeezing = source->squeezing;
    
    return KECCAK_OK;
}

keccak_result
keccak_squeeze (keccak_state *self, unsigned char *buffer, int length)
{
    int bytestocopy;
    
    if (!self->squeezing) {
        keccak_finish (self);
    }
    
    /*
       Support for arbitrary output length
       (not yet used in python module)   
    */
    
    while (length > (self->bufend - self->bufptr)) {
        bytestocopy = (int)(self->bufend - self->bufptr + 1);
        memcpy (buffer, self->bufptr, bytestocopy);
        keccak_function (self->state);
        keccak_squeeze_internal (self);
        self->bufptr = self->buf;
        buffer += bytestocopy;
        length -= bytestocopy;
    }
    memcpy (buffer, self->bufptr, length);
    self->bufptr += length;
    
    return KECCAK_OK;
}

/* Keccak core function */

#define KECCAK_ROUNDS 24

#ifdef KECCAK_USE_BIT_INTERLEAVING
#define ROT_01e 18
#define ROT_01o 18
#define ROT_02e 2
#define ROT_02o 1
#define ROT_03e 21
#define ROT_03o 20
#define ROT_04e 9
#define ROT_04o 9
#define ROT_05e 1
#define ROT_05o 0
#define ROT_06e 22
#define ROT_06o 22
#define ROT_07e 5
#define ROT_07o 5
#define ROT_08e 23
#define ROT_08o 22
#define ROT_09e 1
#define ROT_09o 1
#define ROT_10e 31
#define ROT_10o 31
#define ROT_11e 3
#define ROT_11o 3
#define ROT_12e 22
#define ROT_12o 21
#define ROT_13e 8
#define ROT_13o 7
#define ROT_14e 31
#define ROT_14o 30
#define ROT_15e 14
#define ROT_15o 14
#define ROT_16e 28
#define ROT_16o 27
#define ROT_17e 13
#define ROT_17o 12
#define ROT_18e 11
#define ROT_18o 10
#define ROT_19e 28
#define ROT_19o 28
#define ROT_20e 14
#define ROT_20o 13
#define ROT_21e 10
#define ROT_21o 10
#define ROT_22e 20
#define ROT_22o 19
#define ROT_23e 4
#define ROT_23o 4
#define ROT_24e 7
#define ROT_24o 7

static const uint32_t roundconstants[KECCAK_ROUNDS * 2] = {
    0x00000001UL,    0x00000000UL,
    0x00000000UL,    0x00000089UL,
    0x00000000UL,    0x8000008bUL,
    0x00000000UL,    0x80008080UL,
    0x00000001UL,    0x0000008bUL,
    0x00000001UL,    0x00008000UL,
    0x00000001UL,    0x80008088UL,
    0x00000001UL,    0x80000082UL,
    0x00000000UL,    0x0000000bUL,
    0x00000000UL,    0x0000000aUL,
    0x00000001UL,    0x00008082UL,
    0x00000000UL,    0x00008003UL,
    0x00000001UL,    0x0000808bUL,
    0x00000001UL,    0x8000000bUL,
    0x00000001UL,    0x8000008aUL,
    0x00000001UL,    0x80000081UL,
    0x00000000UL,    0x80000081UL,
    0x00000000UL,    0x80000008UL,
    0x00000000UL,    0x00000083UL,
    0x00000000UL,    0x80008003UL,
    0x00000001UL,    0x80008088UL,
    0x00000000UL,    0x80000088UL,
    0x00000001UL,    0x00008000UL,
    0x00000000UL,    0x80008082UL
};
#else /* use 64 bit instructions */

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
#endif /* KECCAK_USE_BIT_INTERLEAVING */

void
#ifdef KECCAK_USE_BIT_INTERLEAVING
keccak_function (uint32_t *state)
#else
keccak_function (uint64_t *state)
#endif
{
    short i;
        
#ifdef KECCAK_USE_BIT_INTERLEAVING
    /* Temporary variables to avoid indexing overhead */
    uint32_t a0e, a0o;
    uint32_t a1e, a1o;
    uint32_t a2e, a2o;
    uint32_t a3e, a3o;
    uint32_t a4e, a4o;
    uint32_t a5e, a5o;
    uint32_t a6e, a6o;
    uint32_t a7e, a7o;
    uint32_t a8e, a8o;
    uint32_t a9e, a9o;
    uint32_t a10e, a10o;
    uint32_t a11e, a11o;
    uint32_t a12e, a12o;
    uint32_t a13e, a13o;
    uint32_t a14e, a14o;
    uint32_t a15e, a15o;
    uint32_t a16e, a16o;
    uint32_t a17e, a17o;
    uint32_t a18e, a18o;
    uint32_t a19e, a19o;
    uint32_t a20e, a20o;
    uint32_t a21e, a21o;
    uint32_t a22e, a22o;
    uint32_t a23e, a23o;
    uint32_t a24e, a24o;

    uint32_t b0e, b0o;
    uint32_t b1e, b1o;
    uint32_t b2e, b2o;
    uint32_t b3e, b3o;
    uint32_t b4e, b4o;
    uint32_t b5e, b5o;
    uint32_t b6e, b6o;
    uint32_t b7e, b7o;
    uint32_t b8e, b8o;
    uint32_t b9e, b9o;
    uint32_t b10e, b10o;
    uint32_t b11e, b11o;
    uint32_t b12e, b12o;
    uint32_t b13e, b13o;
    uint32_t b14e, b14o;
    uint32_t b15e, b15o;
    uint32_t b16e, b16o;
    uint32_t b17e, b17o;
    uint32_t b18e, b18o;
    uint32_t b19e, b19o;
    uint32_t b20e, b20o;
    uint32_t b21e, b21o;
    uint32_t b22e, b22o;
    uint32_t b23e, b23o;
    uint32_t b24e, b24o;
    
    uint32_t c0e, c0o, c1e, c1o, c2e, c2o, c3e, c3o, c4e, c4o, xe, xo;
    
    a0o  = state[0];
    a0e  = state[1];
    a1o  = state[2];
    a1e  = state[3];
    a2o  = state[4];
    a2e  = state[5];
    a3o  = state[6];
    a3e  = state[7];
    a4o  = state[8];
    a4e  = state[9];
    a5o  = state[10];
    a5e  = state[11];
    a6o  = state[12];
    a6e  = state[13];
    a7o  = state[14];
    a7e  = state[15];
    a8o  = state[16];
    a8e  = state[17];
    a9o  = state[18];
    a9e  = state[19];
    a10o = state[20];
    a10e = state[21];
    a11o = state[22];
    a11e = state[23];
    a12o = state[24];
    a12e = state[25];
    a13o = state[26];
    a13e = state[27];
    a14o = state[28];
    a14e = state[29];
    a15o = state[30];
    a15e = state[31];
    a16o = state[32];
    a16e = state[33];
    a17o = state[34];
    a17e = state[35];
    a18o = state[36];
    a18e = state[37];
    a19o = state[38];
    a19e = state[39];
    a20o = state[40];
    a20e = state[41];
    a21o = state[42];
    a21e = state[43];
    a22o = state[44];
    a22e = state[45];
    a23o = state[46];
    a23e = state[47];
    a24o = state[48];
    a24e = state[49];

    for (i = 0; i < KECCAK_ROUNDS * 2; i += 2) {
        /*
           Uses temporary variables and loop unrolling to
           avoid array indexing and inner loops overhead
        */
        
        /* Prepare column parity for Theta step */
        c0e = a0e ^ a5e ^ a10e ^ a15e ^ a20e;
        c1e = a1e ^ a6e ^ a11e ^ a16e ^ a21e;
        c2e = a2e ^ a7e ^ a12e ^ a17e ^ a22e;
        c3e = a3e ^ a8e ^ a13e ^ a18e ^ a23e;  
        c4e = a4e ^ a9e ^ a14e ^ a19e ^ a24e;
        c0o = a0o ^ a5o ^ a10o ^ a15o ^ a20o;
        c1o = a1o ^ a6o ^ a11o ^ a16o ^ a21o;
        c2o = a2o ^ a7o ^ a12o ^ a17o ^ a22o;
        c3o = a3o ^ a8o ^ a13o ^ a18o ^ a23o;  
        c4o = a4o ^ a9o ^ a14o ^ a19o ^ a24o;
        
        /* Theta + Rho + Pi steps */
        xe   = c4e ^ ROL(c1o, 1);
        xo   = c4o ^ c1e;
        b0e  = a0e ^ xe;
        b0o  = a0o ^ xo;
        b16e = ROL(a5e  ^ xe, ROT_01e);
        b16o = ROL(a5o  ^ xo, ROT_01o);      
        b7e  = ROL(a10o ^ xo, ROT_02e);
        b7o  = ROL(a10e ^ xe, ROT_02o);
        b23e = ROL(a15o ^ xo, ROT_03e);
        b23o = ROL(a15e ^ xe, ROT_03o);
        b14e = ROL(a20e ^ xe, ROT_04e);
        b14o = ROL(a20o ^ xo, ROT_04o);
        
        xe   = c0e ^ ROL(c2o, 1);
        xo   = c0o ^ c2e;
        b10o = a1e ^ xe; 
        b10e = ROL(a1o  ^ xo, ROT_05e);
        b1e  = ROL(a6e  ^ xe, ROT_06e);
        b1o  = ROL(a6o  ^ xo, ROT_06o);
        b17e = ROL(a11e ^ xe, ROT_07e);
        b17o = ROL(a11o ^ xo, ROT_07o);
        b8e  = ROL(a16o ^ xo, ROT_08e);
        b8o  = ROL(a16e ^ xe, ROT_08o);
        b24e = ROL(a21e ^ xe, ROT_09e);
        b24o = ROL(a21o ^ xo, ROT_09o);
        
        xe   = c1e ^ ROL(c3o, 1);
        xo   = c1o ^ c3e;
        b20e = ROL(a2e  ^ xe, ROT_10e);
        b20o = ROL(a2o  ^ xo, ROT_10o);
        b11e = ROL(a7e  ^ xe, ROT_11e);
        b11o = ROL(a7o  ^ xo, ROT_11o);             
        b2e  = ROL(a12o ^ xo, ROT_12e);
        b2o  = ROL(a12e ^ xe, ROT_12o);
        b18e = ROL(a17o ^ xo, ROT_13e);
        b18o = ROL(a17e ^ xe, ROT_13o);
        b9e  = ROL(a22o ^ xo, ROT_14e);
        b9o  = ROL(a22e ^ xe, ROT_14o);
        
        xe   = c2e ^ ROL(c4o, 1);
        xo   = c2o ^ c4e;
        b5e  = ROL(a3e  ^ xe, ROT_15e);
        b5o  = ROL(a3o  ^ xo, ROT_15o); 
        b21e = ROL(a8o  ^ xo, ROT_16e);
        b21o = ROL(a8e  ^ xe, ROT_16o);
        b12e = ROL(a13o ^ xo, ROT_17e);
        b12o = ROL(a13e ^ xe, ROT_17o);                      
        b3e  = ROL(a18o ^ xo, ROT_18e);
        b3o  = ROL(a18e ^ xe, ROT_18o);
        b19e = ROL(a23e ^ xe, ROT_19e);
        b19o = ROL(a23o ^ xo, ROT_19o);
        
        xe   = c3e ^ ROL(c0o, 1);
        xo   = c3o ^ c0e;
        b15e = ROL(a4o  ^ xo, ROT_20e);
        b15o = ROL(a4e  ^ xe, ROT_20o);
        b6e  = ROL(a9e  ^ xe, ROT_21e);
        b6o  = ROL(a9o  ^ xo, ROT_21o);
        b22e = ROL(a14o ^ xo, ROT_22e);
        b22o = ROL(a14e ^ xe, ROT_22o);
        b13e = ROL(a19e ^ xe, ROT_23e);
        b13o = ROL(a19o ^ xo, ROT_23o);
        b4e  = ROL(a24e ^ xe, ROT_24e);
        b4o  = ROL(a24o ^ xo, ROT_24o);
            
        /* Chi + Iota steps */
#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
        a0e = b0e ^ ( b1e | b2e) ^ roundconstants[i];
        a1e = b1e ^ (~b2e | b3e);
        a2e = b2e ^ ( b3e & b4e);
        a3e = b3e ^ ( b4e | b0e);
        a4e = b4e ^ ( b0e & b1e);
        
        a5e = b5e ^ ( b6e |  b7e);
        a6e = b6e ^ ( b7e &  b8e);
        a7e = b7e ^ ( b8e | ~b9e);
        a8e = b8e ^ ( b9e |  b5e);
        a9e = b9e ^ ( b5e &  b6e);
        
        a10e =  b10e ^ ( b11e |  b12e);
        a11e =  b11e ^ ( b12e &  b13e);
        a12e =  b12e ^ (~b13e &  b14e);
        a13e = ~b13e ^ ( b14e |  b10e);
        a14e =  b14e ^ ( b10e &  b11e);
        
        a15e =  b15e ^ ( b16e & b17e);
        a16e =  b16e ^ ( b17e | b18e);
        a17e =  b17e ^ (~b18e | b19e);
        a18e = ~b18e ^ ( b19e & b15e);
        a19e =  b19e ^ ( b15e | b16e);
        
        a20e =  b20e ^ (~b21e & b22e);
        a21e = ~b21e ^ ( b22e | b23e);
        a22e =  b22e ^ ( b23e & b24e);
        a23e =  b23e ^ ( b24e | b20e);
        a24e =  b24e ^ ( b20e & b21e);
        
        a0o = b0o ^ ( b1o | b2o) ^ roundconstants[i + 1];
        a1o = b1o ^ (~b2o | b3o);
        a2o = b2o ^ ( b3o & b4o);
        a3o = b3o ^ ( b4o | b0o);
        a4o = b4o ^ ( b0o & b1o);
        
        a5o = b5o ^ ( b6o |  b7o);
        a6o = b6o ^ ( b7o &  b8o);
        a7o = b7o ^ ( b8o | ~b9o);
        a8o = b8o ^ ( b9o |  b5o);
        a9o = b9o ^ ( b5o &  b6o);
        
        a10o =  b10o ^ ( b11o |  b12o);
        a11o =  b11o ^ ( b12o &  b13o);
        a12o =  b12o ^ (~b13o &  b14o);
        a13o = ~b13o ^ ( b14o |  b10o);
        a14o =  b14o ^ ( b10o &  b11o);
        
        a15o =  b15o ^ ( b16o & b17o);
        a16o =  b16o ^ ( b17o | b18o);
        a17o =  b17o ^ (~b18o | b19o);
        a18o = ~b18o ^ ( b19o & b15o);
        a19o =  b19o ^ ( b15o | b16o);
        
        a20o =  b20o ^ (~b21o & b22o);
        a21o = ~b21o ^ ( b22o | b23o);
        a22o =  b22o ^ ( b23o & b24o);
        a23o =  b23o ^ ( b24o | b20o);
        a24o =  b24o ^ ( b20o & b21o);
        
#else
        a0e  = b0e  ^ (~b1e  & b2e) ^ roundconstants[i];
        a1e  = b1e  ^ (~b2e  & b3e);
        a2e  = b2e  ^ (~b3e  & b4e);
        a3e  = b3e  ^ (~b4e  & b0e);
        a4e  = b4e  ^ (~b0e  & b1e);
        
        a5e  = b5e  ^ (~b6e  & b7e);
        a6e  = b6e  ^ (~b7e  & b8e);
        a7e  = b7e  ^ (~b8e  & b9e);
        a8e  = b8e  ^ (~b9e  & b5e);
        a9e  = b9e  ^ (~b5e  & b6e);
        
        a10e = b10e ^ (~b11e & b12e);
        a11e = b11e ^ (~b12e & b13e);        
        a12e = b12e ^ (~b13e & b14e);
        a13e = b13e ^ (~b14e & b10e);
        a14e = b14e ^ (~b10e & b11e);
        
        a15e = b15e ^ (~b16e & b17e);
        a16e = b16e ^ (~b17e & b18e);
        a17e = b17e ^ (~b18e & b19e);
        a18e = b18e ^ (~b19e & b15e);
        a19e = b19e ^ (~b15e & b16e);
        
        a20e = b20e ^ (~b21e & b22e);
        a21e = b21e ^ (~b22e & b23e);
        a22e = b22e ^ (~b23e & b24e);
        a23e = b23e ^ (~b24e & b20e);
        a24e = b24e ^ (~b20e & b21e);
        
        a0o  = b0o  ^ (~b1o  & b2o) ^ roundconstants[i + 1];
        a1o  = b1o  ^ (~b2o  & b3o);
        a2o  = b2o  ^ (~b3o  & b4o);
        a3o  = b3o  ^ (~b4o  & b0o);
        a4o  = b4o  ^ (~b0o  & b1o);
        
        a5o  = b5o  ^ (~b6o  & b7o);
        a6o  = b6o  ^ (~b7o  & b8o);
        a7o  = b7o  ^ (~b8o  & b9o);
        a8o  = b8o  ^ (~b9o  & b5o);
        a9o  = b9o  ^ (~b5o  & b6o);
        
        a10o = b10o ^ (~b11o & b12o);
        a11o = b11o ^ (~b12o & b13o);        
        a12o = b12o ^ (~b13o & b14o);
        a13o = b13o ^ (~b14o & b10o);
        a14o = b14o ^ (~b10o & b11o);
        
        a15o = b15o ^ (~b16o & b17o);
        a16o = b16o ^ (~b17o & b18o);
        a17o = b17o ^ (~b18o & b19o);
        a18o = b18o ^ (~b19o & b15o);
        a19o = b19o ^ (~b15o & b16o);
        
        a20o = b20o ^ (~b21o & b22o);
        a21o = b21o ^ (~b22o & b23o);
        a22o = b22o ^ (~b23o & b24o);
        a23o = b23o ^ (~b24o & b20o);
        a24o = b24o ^ (~b20o & b21o);
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */
    }

    state[0]  = a0o;
    state[1]  = a0e;
    state[2]  = a1o;   
    state[3]  = a1e;
    state[4]  = a2o;
    state[5]  = a2e;
    state[6]  = a3o;
    state[7]  = a3e;    
    state[8]  = a4o;
    state[9]  = a4e;
    state[10] = a5o;
    state[11] = a5e;
    state[12] = a6o;   
    state[13] = a6e;
    state[14] = a7o;
    state[15] = a7e;
    state[16] = a8o;
    state[17] = a8e;    
    state[18] = a9o;
    state[19] = a9e;
    state[20] = a10o;   
    state[21] = a10e;
    state[22] = a11o;
    state[23] = a11e;
    state[24] = a12o;
    state[25] = a12e;
    state[26] = a13o;
    state[27] = a13e;   
    state[28] = a14o;
    state[29] = a14e;
    state[30] = a15o;
    state[31] = a15e;
    state[32] = a16o;    
    state[33] = a16e;
    state[34] = a17o;
    state[35] = a17e;
    state[36] = a18o;
    state[37] = a18e;   
    state[38] = a19o;
    state[39] = a19e;
    state[40] = a20o;
    state[41] = a20e;
    state[42] = a21o;    
    state[43] = a21e;
    state[44] = a22o;
    state[45] = a22e;   
    state[46] = a23o;
    state[47] = a23e;
    state[48] = a24o;
    state[49] = a24e;
    
#else /* use 64 bit instructions */

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
#ifdef USE_COMPLEMENT_LANES_OPTIMIZATION
        a0 = b0 ^ ( b1 | b2) ^ roundconstants[i];
        a1 = b1 ^ (~b2 | b3);
        a2 = b2 ^ ( b3 & b4);
        a3 = b3 ^ ( b4 | b0);
        a4 = b4 ^ ( b0 & b1);
        
        a5 = b5 ^ ( b6 |  b7);
        a6 = b6 ^ ( b7 &  b8);
        a7 = b7 ^ ( b8 | ~b9);
        a8 = b8 ^ ( b9 |  b5);
        a9 = b9 ^ ( b5 &  b6);
        
        a10 =  b10 ^ ( b11 |  b12);
        a11 =  b11 ^ ( b12 &  b13);
        a12 =  b12 ^ (~b13 &  b14);
        a13 = ~b13 ^ ( b14 |  b10);
        a14 =  b14 ^ ( b10 &  b11);
        
        a15 =  b15 ^ ( b16 & b17);
        a16 =  b16 ^ ( b17 | b18);
        a17 =  b17 ^ (~b18 | b19);
        a18 = ~b18 ^ ( b19 & b15);
        a19 =  b19 ^ ( b15 | b16);
        
        a20 =  b20 ^ (~b21 & b22);
        a21 = ~b21 ^ ( b22 | b23);
        a22 =  b22 ^ ( b23 & b24);
        a23 =  b23 ^ ( b24 | b20);
        a24 =  b24 ^ ( b20 & b21);
#else /* not USE_COMPLEMENT_LANES_OPTIMIZATION */
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
#endif /* USE_COMPLEMENT_LANES_OPTIMIZATION */
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
#endif /* KECCAK_USE_BIT_INTERLEAVING */
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */


