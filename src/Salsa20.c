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
#include "libtom/tomcrypt_cfg.h"
#include "libtom/tomcrypt_custom.h"
#include "libtom/tomcrypt_macros.h"

#define MODULE_NAME _Salsa20
#define BLOCK_SIZE 1
#define KEY_SIZE 0
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

#define _MODULE_CUSTOM_FUNCTION _salsa20_8_core

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

/*
 * Salsa20/8 Core function (combined with XOR)
 *
 * This function accepts two 64-byte Python byte strings (x and y).
 * It creates a new 64-byte Python byte string with the result
 * of the expression salsa20_8(xor(x,y)).
 */
static PyObject *
ALG_salsa20_8_core(PyObject *self, PyObject *args, PyObject *kwdict)
{
    PyObject *input_str;
    PyObject *previous_input_str;
    uint8_t *input_bytes;
    uint8_t *previous_input_bytes;
    uint8_t *output_bytes;
    uint32_t input_32[16];
    PyObject *output;
    int i;

    output = NULL;

    if (!PyArg_ParseTuple(args, "SS", &previous_input_str, &input_str)) {
        goto out;
    }

    if (PyBytes_GET_SIZE(previous_input_str)!=64 ||
            PyBytes_GET_SIZE(input_str)!=64) {
        goto out;
    }

    output = PyBytes_FromStringAndSize(NULL, 64);
    if (!output) {
        goto out;
    }

    previous_input_bytes = (uint8_t*)PyBytes_AS_STRING(previous_input_str);
    input_bytes = (uint8_t*)PyBytes_AS_STRING(input_str);
    for (i=0; i<16; i++) {
        uint32_t tmp;

        U8TO32_LITTLE(tmp, &previous_input_bytes[i*4]);
        U8TO32_LITTLE(input_32[i], &input_bytes[i*4]);
        input_32[i] ^= tmp;
    }
    output_bytes = (uint8_t*)PyBytes_AS_STRING(output);

    Py_BEGIN_ALLOW_THREADS;
    _salsa20_block(8, input_32, output_bytes);
    Py_END_ALLOW_THREADS;

out:
    return output;
}

static void
stream_init (stream_state *self, unsigned char *key, int keylen,
			 unsigned char *nonce, int nonce_len)
{
    const char *constants;
    uint32_t *input;
    
    if (keylen != 16 && keylen != 32) {
        PyErr_SetString(PyExc_ValueError,
            "Salsa20 key must be 16 or 32 bytes long");
        return;
    }
    if (nonce_len != 8) {
        char buf[160];
        sprintf(buf, "Salsa20 nonce must be 8 bytes long"
                     " (got %d)", nonce_len);
        PyErr_SetString(PyExc_ValueError, buf);
        return;
    }
    
    input = self->input;
    
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
    self->blockindex = 64;
}

/* Encryption and decryption are symmetric */
#define stream_decrypt stream_encrypt	

static void
stream_encrypt (stream_state *self, unsigned char *buffer, int len)
{
    int i;
    for (i = 0; i < len; ++i) {
        if (self->blockindex == 64) {
            self->blockindex = 0;
            _salsa20_block(ROUNDS, self->input, self->block);
        }
        buffer[i] ^= self->block[self->blockindex];
        self->blockindex ++;
    }
}

#define STREAM_CIPHER_NEEDS_NONCE
#include "stream_template.c"

/* vim:set ts=4 sw=4 sts=4 expandtab: */
