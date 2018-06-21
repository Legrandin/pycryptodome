/*
 *
 *  Blowfish.c : Blowfish implementation
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the extent
 * that dedication to the public domain is not available, everyone is granted a
 * worldwide, perpetual, royalty-free, non-exclusive license to exercise all
 * rights associated with the contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 *
 * Country of origin: Canada
 *
 * The Blowfish algorithm is documented at
 * http://www.schneier.com/paper-blowfish-fse.html
 */

#include "common.h"
#include "block_base.h"

FAKE_INIT(raw_blowfish)

#include "Blowfish-tables.h"

#define MODULE_NAME Blowfish
#define BLOCK_SIZE 8    /* 64-bit block size */
#define KEY_SIZE 0      /* variable key size */

#define BLOWFISH_MAGIC 0xf9d565deu
struct block_state {
    uint32_t magic;

    /* P permutation */
    uint32_t P[18];

    /* Subkeys (S-boxes) */
    uint32_t S1[256];
    uint32_t S2[256];
    uint32_t S3[256];
    uint32_t S4[256];
};

/* The Blowfish round function F.  Everything is taken modulo 2**32 */
#define F(a, b, c, d) (((a) + (b)) ^ (c)) + (d)

static void inline_encrypt(struct block_state *self, uint32_t *pxL, uint32_t *pxR)
{
    int i;
    uint32_t xL = *pxL;
    uint32_t xR = *pxR;
    uint32_t tmp;

    for (i = 0; i < 16; i++) {
        xL ^= self->P[i];

        /* a || b || c || d = xL (big endian) */
        xR ^= F(self->S1[(xL >> 24) & 0xff],    /* S1[a] */
                self->S2[(xL >> 16) & 0xff],    /* S2[b] */
                self->S3[(xL >> 8) & 0xff],     /* S3[c] */
                self->S4[xL & 0xff]);           /* S4[d] */

        /* Swap xL, xR */
        tmp = xL; xL = xR; xR = tmp;
    }

    /* Swap xL, xR */
    tmp = xL; xL = xR; xR = tmp;

    xR ^= self->P[16];
    xL ^= self->P[17];

    *pxL = xL;
    *pxR = xR;
}

static void inline_decrypt(struct block_state *self, uint32_t *pxL, uint32_t *pxR)
{
    int i;
    uint32_t xL = *pxL;
    uint32_t xR = *pxR;
    uint32_t tmp;

    xL ^= self->P[17];
    xR ^= self->P[16];

    /* Swap xL, xR */
    tmp = xL; xL = xR; xR = tmp;

    for (i = 15; i >= 0; i--) {
        /* Swap xL, xR */
        tmp = xL; xL = xR; xR = tmp;

        /* a || b || c || d = xL (big endian) */
        xR ^= F(self->S1[(xL >> 24) & 0xff],    /* S1[a] */
                self->S2[(xL >> 16) & 0xff],    /* S2[b] */
                self->S3[(xL >> 8) & 0xff],     /* S3[c] */
                self->S4[xL & 0xff]);           /* S4[d] */

        xL ^= self->P[i];
    }

    *pxL = xL;
    *pxR = xR;
}

static void block_encrypt(struct block_state *self, const uint8_t *in, unsigned char *out)
{
    uint32_t xL, xR;

    /* big endian */
    xL = LOAD_U32_BIG(in);
    xR = LOAD_U32_BIG(in+4);

    inline_encrypt(self, &xL, &xR);

    /* big endian */
    STORE_U32_BIG(out, xL);
    STORE_U32_BIG(out+4, xR);
}

static void block_decrypt(struct block_state *self, const uint8_t *in, unsigned char *out)
{
    uint32_t xL, xR;

    /* big endian */
    xL = LOAD_U32_BIG(in);
    xR = LOAD_U32_BIG(in+4);

    inline_decrypt(self, &xL, &xR);

    /* big endian */
    STORE_U32_BIG(out, xL);
    STORE_U32_BIG(out+4, xR);
}

static int block_init(struct block_state *self, const uint8_t *key, size_t keylen)
{
    uint32_t word;
    unsigned i;
    uint32_t xL, xR;

    self->magic = 0;

    if (keylen < 1) {
        return ERR_KEY_SIZE;
    }

    /* Initialize the P-array with the digits of Pi, and XOR it with the key */
    word = 0;
    for (i = 0; i < 18*4; i++) {
        word = (word << 8) | key[i % keylen];
        if ((i & 3) == 3) {
            self->P[i >> 2] = initial_P[i >> 2] ^ word;
            word = 0;
        }
    }

    /* Initialize the S-boxes with more digits of Pi */
    memcpy(self->S1, initial_S1, 256*sizeof(uint32_t));
    memcpy(self->S2, initial_S2, 256*sizeof(uint32_t));
    memcpy(self->S3, initial_S3, 256*sizeof(uint32_t));
    memcpy(self->S4, initial_S4, 256*sizeof(uint32_t));

    /* Stir the subkeys */
    xL = xR = 0;
    for (i = 0; i < 18; i += 2) {
        inline_encrypt(self, &xL, &xR);
        self->P[i] = xL;
        self->P[i+1] = xR;
    }
    for (i = 0; i < 256; i += 2) {
        inline_encrypt(self, &xL, &xR);
        self->S1[i] = xL;
        self->S1[i+1] = xR;
    }
    for (i = 0; i < 256; i += 2) {
        inline_encrypt(self, &xL, &xR);
        self->S2[i] = xL;
        self->S2[i+1] = xR;
    }
    for (i = 0; i < 256; i += 2) {
        inline_encrypt(self, &xL, &xR);
        self->S3[i] = xL;
        self->S3[i+1] = xR;
    }
    for (i = 0; i < 256; i += 2) {
        inline_encrypt(self, &xL, &xR);
        self->S4[i] = xL;
        self->S4[i+1] = xR;
    }

    self->magic = BLOWFISH_MAGIC;
    return 0;
}

static void block_finalize(struct block_state *self)
{
}

#include "block_common.c"

/* vim:set ts=4 sw=4 sts=4 expandtab: */
