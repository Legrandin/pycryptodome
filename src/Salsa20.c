/*
 * Salsa20.c : Source for the Salsa20 stream cipher.
 *
 * Part of the Python Cryptography Toolkit
 *
 * Contributed by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>.
 * Based on the reference implementation by D. J. Bernstein
 * <http://cr.yp.to/snuffle/salsa20/regs/salsa20.c>
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the
 * extent that dedication to the public domain is not available, everyone
 * is granted a worldwide, perpetual, royalty-free, non-exclusive license
 * to exercise all rights associated with the contents of this file for
 * any purpose whatsoever.  No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 */

#include "pycrypto_common.h"

FAKE_INIT(Salsa20)

#include "libtom/tomcrypt_cfg.h"
#include "libtom/tomcrypt_custom.h"
#include "libtom/tomcrypt_macros.h"

#define ROUNDS 20
#define MAX_KEY_SIZE 32

static const char sigma[16] = "expand 32-byte k";
static const char tau[16]   = "expand 16-byte k";

#define U32TO8_LITTLE(p,w) STORE32L(w, p)
#define U8TO32_LITTLE(w,p) LOAD32L(w, p)
#define ROTATE(v,c) (ROL(v,c))
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

typedef struct 
{
    uint32_t input[16];
    uint8_t  block[64];
    uint8_t  blockindex;
} stream_state;

static void
_salsa20_block(int rounds, uint32_t *input, uint8_t *output)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint8_t  i;

    x0  = input[0];
    x1  = input[1];
    x2  = input[2];
    x3  = input[3];
    x4  = input[4];
    x5  = input[5];
    x6  = input[6];
    x7  = input[7];
    x8  = input[8];
    x9  = input[9];
    x10 = input[10];
    x11 = input[11];
    x12 = input[12];
    x13 = input[13];
    x14 = input[14];
    x15 = input[15];
    
    for (i = rounds; i > 0; i -= 2) {
        /* Column round */
        x4  = XOR ( x4, ROTATE (PLUS ( x0,x12), 7));
        x8  = XOR ( x8, ROTATE (PLUS ( x4, x0), 9));
        x12 = XOR (x12, ROTATE (PLUS ( x8, x4),13));
        x0  = XOR ( x0, ROTATE (PLUS (x12, x8),18));
        x9  = XOR ( x9, ROTATE (PLUS ( x5, x1), 7));
        x13 = XOR (x13, ROTATE (PLUS ( x9, x5), 9));
        x1  = XOR ( x1, ROTATE (PLUS (x13, x9),13));
        x5  = XOR ( x5, ROTATE (PLUS ( x1,x13),18));
        x14 = XOR (x14, ROTATE (PLUS (x10, x6), 7));
        x2  = XOR ( x2, ROTATE (PLUS (x14,x10), 9));
        x6  = XOR ( x6, ROTATE (PLUS ( x2,x14),13));
        x10 = XOR (x10, ROTATE (PLUS ( x6, x2),18));
        x3  = XOR ( x3, ROTATE (PLUS (x15,x11), 7));
        x7  = XOR ( x7, ROTATE (PLUS ( x3,x15), 9));
        x11 = XOR (x11, ROTATE (PLUS ( x7, x3),13));
        x15 = XOR (x15, ROTATE (PLUS (x11, x7),18));
        
        /* Row round */
        x1  = XOR ( x1, ROTATE (PLUS ( x0, x3), 7));
        x2  = XOR ( x2, ROTATE (PLUS ( x1, x0), 9));
        x3  = XOR ( x3, ROTATE (PLUS ( x2, x1),13));
        x0  = XOR ( x0, ROTATE (PLUS ( x3, x2),18));
        x6  = XOR ( x6, ROTATE (PLUS ( x5, x4), 7));
        x7  = XOR ( x7, ROTATE (PLUS ( x6, x5), 9));
        x4  = XOR ( x4, ROTATE (PLUS ( x7, x6),13));
        x5  = XOR ( x5, ROTATE (PLUS ( x4, x7),18));
        x11 = XOR (x11, ROTATE (PLUS (x10, x9), 7));
        x8  = XOR ( x8, ROTATE (PLUS (x11,x10), 9));
        x9  = XOR ( x9, ROTATE (PLUS ( x8,x11),13));
        x10 = XOR (x10, ROTATE (PLUS ( x9, x8),18));
        x12 = XOR (x12, ROTATE (PLUS (x15,x14), 7));
        x13 = XOR (x13, ROTATE (PLUS (x12,x15), 9));
        x14 = XOR (x14, ROTATE (PLUS (x13,x12),13));
        x15 = XOR (x15, ROTATE (PLUS (x14,x13),18));
    }
    
    x0  = PLUS (x0, input[0]);
    x1  = PLUS (x1, input[1]);
    x2  = PLUS (x2, input[2]);
    x3  = PLUS (x3, input[3]);
    x4  = PLUS (x4, input[4]);
    x5  = PLUS (x5, input[5]);
    x6  = PLUS (x6, input[6]);
    x7  = PLUS (x7, input[7]);
    x8  = PLUS (x8, input[8]);
    x9  = PLUS (x9, input[9]);
    x10 = PLUS (x10, input[10]);
    x11 = PLUS (x11, input[11]);
    x12 = PLUS (x12, input[12]);
    x13 = PLUS (x13, input[13]);
    x14 = PLUS (x14, input[14]);
    x15 = PLUS (x15, input[15]);
    
    U32TO8_LITTLE (output + 0, x0);
    U32TO8_LITTLE (output + 4, x1);
    U32TO8_LITTLE (output + 8, x2);
    U32TO8_LITTLE (output + 12, x3);
    U32TO8_LITTLE (output + 16, x4);
    U32TO8_LITTLE (output + 20, x5);
    U32TO8_LITTLE (output + 24, x6);
    U32TO8_LITTLE (output + 28, x7);
    U32TO8_LITTLE (output + 32, x8);
    U32TO8_LITTLE (output + 36, x9);
    U32TO8_LITTLE (output + 40, x10);
    U32TO8_LITTLE (output + 44, x11);
    U32TO8_LITTLE (output + 48, x12);
    U32TO8_LITTLE (output + 52, x13);
    U32TO8_LITTLE (output + 56, x14);
    U32TO8_LITTLE (output + 60, x15);
    
    /* Increment block counter */
    input[8] = PLUSONE (input[8]);
    if (!input[8]) {
        input[9] = PLUSONE (input[9]);
        /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
}

static int little_endian(void) {
    int test = 1;
    return *((uint8_t*)&test) == 1;
}

EXPORT_SYM uint32_t load_le_uint32(const uint8_t *in)
{
    union {
        uint32_t w;
        uint8_t b[4];
    } x, y;

    memcpy(&x, in, 4);
    y = x;
    if (!little_endian()) {
        y.b[0] = x.b[3];
        y.b[1] = x.b[2];
        y.b[2] = x.b[1];
        y.b[3] = x.b[0];
    }
    return y.w;
}

/*
 * Salsa20/8 Core function (combined with XOR)
 *
 * This function accepts two 64-byte Python byte strings (x and y).
 * It creates a new 64-byte Python byte string with the result
 * of the expression salsa20_8(xor(x,y)).
 */
EXPORT_SYM int Salsa20_8_core(const uint8_t *x, const uint8_t *y, uint8_t *out)
{
    uint32_t input_32[16];
    int i;

    if (NULL==x || NULL==y || NULL==out)
        return ERR_NULL;

    for (i=0; i<16; i++) {
        uint32_t tmp;

        U8TO32_LITTLE(tmp, &x[i*4]);
        U8TO32_LITTLE(input_32[i], &y[i*4]);
        input_32[i] ^= tmp;
    }

    _salsa20_block(8, input_32, out);
    return 0;
}

EXPORT_SYM int Salsa20_stream_init(uint8_t *key, size_t keylen,
                        uint8_t *nonce, size_t nonce_len,
                        stream_state **pSalsaState)
{
    const char *constants;
    uint32_t *input;
    stream_state *salsaState;

    if (NULL == pSalsaState || NULL == key || NULL == nonce)
        return ERR_NULL;

    if (keylen != 16 && keylen != 32)
        return ERR_KEY_SIZE;

    if (nonce_len != 8)
        return ERR_NONCE_SIZE;
    
    *pSalsaState = salsaState = calloc(1, sizeof(stream_state));
    if (NULL == salsaState)
        return ERR_MEMORY;

    input = salsaState->input;
    
    U8TO32_LITTLE (input[1], key);
    U8TO32_LITTLE (input[2], key + 4);
    U8TO32_LITTLE (input[3], key + 8);
    U8TO32_LITTLE (input[4], key + 12);
    
    if (keylen == 32) {
        key += 16;
        constants = sigma;
    } else {
        constants = tau;
    }

    U8TO32_LITTLE (input[11], key + 0);
    U8TO32_LITTLE (input[12], key + 4);
    U8TO32_LITTLE (input[13], key + 8);
    U8TO32_LITTLE (input[14], key + 12);
    U8TO32_LITTLE (input[0],  constants);
    U8TO32_LITTLE (input[5],  constants + 4);
    U8TO32_LITTLE (input[10], constants + 8);
    U8TO32_LITTLE (input[15], constants + 12);
    
    /* nonce setup */
    U8TO32_LITTLE (input[6], nonce);
    U8TO32_LITTLE (input[7], nonce + 4);
    
    /* Block counter setup*/
    input[8]  = 0;
    input[9]  = 0;
    salsaState->blockindex = 64;
    return 0;
}

EXPORT_SYM int Salsa20_stream_destroy(stream_state *salsaState)
{
    free(salsaState);
    return 0;
}

EXPORT_SYM int Salsa20_stream_encrypt(stream_state *salsaState, const uint8_t in[],
                           uint8_t out[], size_t len)
{
    unsigned i;
    for (i = 0; i < len; ++i) {
        if (salsaState->blockindex == 64) {
            salsaState->blockindex = 0;
            _salsa20_block(ROUNDS, salsaState->input, salsaState->block);
        }
        out[i] = in[i] ^ salsaState->block[salsaState->blockindex];
        salsaState->blockindex++;
    }
    return 0;
}
