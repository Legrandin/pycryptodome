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

#ifndef __KECCAK_H_
#define __KECCAK_H_

#include "pycrypto_common.h"

typedef struct
{
    uint64_t state[25];
    uint8_t  buf[200];
    uint8_t *bufptr;
    uint8_t *bufend;
    uint16_t security;
    uint16_t capacity;
    uint16_t rate;
    uint8_t  squeezing;
} keccak_state;

typedef enum {
    KECCAK_OK,
    KECCAK_ERR_CANTABSORB,
    KECCAK_ERR_INVALIDPARAM,
    KECCAK_ERR_UNKNOWNPARAM,
    KECCAK_ERR_NOTIMPL
} keccak_result;

typedef enum {
    KECCAK_INIT_SECURITY,
    KECCAK_INIT_RATE
} keccak_init_param;


keccak_result keccak_init    (keccak_state *self, unsigned int param, keccak_init_param initby);
keccak_result keccak_finish  (keccak_state *self);
keccak_result keccak_copy    (keccak_state *source, keccak_state *dest);
keccak_result keccak_absorb  (keccak_state *self, unsigned char *buffer, int length);
keccak_result keccak_squeeze (keccak_state *self, unsigned char *buffer, int length);

void keccak_function (uint64_t *state);


#endif /* __KECCAK_H_ */

/* vim:set ts=4 sw=4 sts=4 expandtab: */
