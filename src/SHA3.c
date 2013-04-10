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


/*
    MODULE_NAME and DIGEST_SIZE are defined in compiler command line
    options - see setup.py:
    
    Extension("Crypto.Hash._SHA3_nnn",
              include_dirs=['src/'],
              sources=["src/sha3.c"],
              define_macros=[('MODULE_NAME', '_SHA3_nnn'),
                ('DIGEST_SIZE', '%d' % (nnn/8))]),

*/
#include "config.h"

#define CAPACITY (2*(DIGEST_SIZE))
#define BLOCK_SIZE (200-CAPACITY)

#include <string.h>
#include <time.h>
#include "libtom/tomcrypt_cfg.h"
#include "libtom/tomcrypt_custom.h"
#include "libtom/tomcrypt_macros.h"
#include "Python.h"
#include "pycrypto_compat.h"

/* determine fixed size types */
#if HAVE_STDINT_H
#include <stdint.h>
#elif defined(__sun) || defined(__sun__)
#include <sys/inttypes.h>
#elif defined(_MSC_VER)
typedef unsigned char    uint8_t;
typedef unsigned __int64 uint64_t;
#else
typedef unsigned char      uint8_t;
typedef unsigned long long uint64_t;
#endif

/* define the hash_state structure */
typedef struct
{
    uint64_t state[25];
    uint8_t  buf[BLOCK_SIZE];
    uint8_t *bufptr;
    uint8_t *bufend;
} hash_state;

void hash_init (hash_state *self);
void hash_update (hash_state *self, unsigned char *buffer, int length);
PyObject *hash_digest(hash_state *self);
void hash_copy (hash_state *source, hash_state *dest);

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

static void
keccak_function (uint64_t *state)
{
    short i;
    
    /* Temporary variables to avoid indexing overhead */
    uint64_t a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12;
    uint64_t a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24;
    
    uint64_t b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12;
    uint64_t b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24;
      
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
    
        /* Theta step */
        b0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
        b1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
        b2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
        b3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;  
        b4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
        
        b5   = b4 ^ ROL64(b1, 1);
        a0  ^= b5;
        a5  ^= b5;
        a10 ^= b5;
        a15 ^= b5;
        a20 ^= b5;
        
        b5   = b0 ^ ROL64(b2, 1);        
        a1  ^= b5;
        a6  ^= b5;
        a11 ^= b5;
        a16 ^= b5;
        a21 ^= b5;
        
        b5   = b1 ^ ROL64(b3, 1);
        a2  ^= b5;
        a7  ^= b5;
        a12 ^= b5;
        a17 ^= b5;
        a22 ^= b5;
        
        b5   = b2 ^ ROL64(b4, 1);
        a3  ^= b5;
        a8  ^= b5;
        a13 ^= b5;
        a18 ^= b5;
        a23 ^= b5;
                
        b5   = b3 ^ ROL64(b0, 1);
        a4  ^= b5;
        a9  ^= b5;
        a14 ^= b5;
        a19 ^= b5;
        a24 ^= b5;
        
        /* Rho + Pi steps */
        b0  = a0;
        b1  = ROL64(a6,  ROT_06);
        b2  = ROL64(a12, ROT_12);
        b3  = ROL64(a18, ROT_18);
        b4  = ROL64(a24, ROT_24);
        b5  = ROL64(a3,  ROT_15);
        b6  = ROL64(a9,  ROT_21);
        b7  = ROL64(a10, ROT_02);
        b8  = ROL64(a16, ROT_08);
        b9  = ROL64(a22, ROT_14);
        b10 = ROL64(a1,  ROT_05);
        b11 = ROL64(a7,  ROT_11);
        b12 = ROL64(a13, ROT_17);
        b13 = ROL64(a19, ROT_23);
        b14 = ROL64(a20, ROT_04);
        b15 = ROL64(a4,  ROT_20);
        b16 = ROL64(a5,  ROT_01);
        b17 = ROL64(a11, ROT_07);
        b18 = ROL64(a17, ROT_13);
        b19 = ROL64(a23, ROT_19);
        b20 = ROL64(a2,  ROT_10);
        b21 = ROL64(a8,  ROT_16);
        b22 = ROL64(a14, ROT_22);
        b23 = ROL64(a15, ROT_03);
        b24 = ROL64(a21, ROT_09);
        
        /* Chi step */
        a0  = b0  ^ (~b1  & b2);
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
        
        /* Iota step */
        a0 ^= roundconstants[i];
    }
    
    state[0] = a0;
    state[1] = a1;
    state[2] = a2;
    state[3] = a3;
    state[4] = a4;
    state[5] = a5;
    state[6] = a6;
    state[7] = a7;
    state[8] = a8;
    state[9] = a9;
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

static void
keccak_absorb (hash_state *self)
{
    short i,j;
    uint64_t d;
    
    for (i = j = 0; j < BLOCK_SIZE; ++i, j += 8) {
        LOAD64L(d, self->buf + j);
        self->state[i] ^= d;
    }
}

static void
keccak_finish (hash_state *self)
{
    /* Padding */
    *(self->bufptr++) = 0x01U;
    memset (self->bufptr, 0, self->bufend - self->bufptr);
    *(self->bufend) = 0x80U;
    self->bufptr = self->bufend;
    
    /* Final absord */
    keccak_absorb (self);
    keccak_function (self->state);
}


void
hash_init (hash_state *self)
{   
    memset (self, 0, sizeof(hash_state));
    self->bufptr = self->buf;
    self->bufend = self->buf + BLOCK_SIZE - 1;
}

void
hash_update (hash_state *self, unsigned char *buffer, int length)
{
    int bytestocopy;
    
    while (self->bufptr + length > self->bufend) {
        bytestocopy = self->bufend - self->bufptr + 1;
        memcpy (self->bufptr, buffer, bytestocopy);
        keccak_absorb (self);
        keccak_function (self->state);
        self->bufptr = self->buf;
        buffer += bytestocopy;
        length -= bytestocopy;
    }
    memcpy (self->bufptr, buffer, length);
    self->bufptr += length;
}

void
hash_copy (hash_state *source, hash_state *dest)
{
    memcpy (dest->state, source->state, 25 * sizeof(uint64_t));
    memcpy (dest->buf, source->buf, BLOCK_SIZE);
    dest->bufptr = dest->buf + (source->bufptr - source->buf);
    dest->bufend = dest->buf + BLOCK_SIZE - 1;
}


PyObject
*hash_digest (hash_state *self)
{
    int i, j;
    hash_state tmp;
    
    hash_copy (self, &tmp);
    keccak_finish (&tmp);
    for (i = j = 0; j < DIGEST_SIZE; ++i, j += 8) {
        STORE64L(tmp.state[i], tmp.buf + j);
    }
    
	return PyBytes_FromStringAndSize ((char *)tmp.buf, DIGEST_SIZE);
}

#include "hash_template.c"

/* vim:set ts=4 sw=4 sts=4 expandtab: */
