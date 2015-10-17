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

#include <time.h> /* libtom requires definition of clock_t */
#include "libtom/tomcrypt_cfg.h"
#include "libtom/tomcrypt_custom.h"
#include "libtom/tomcrypt_macros.h"

#ifdef ENDIAN_32BITWORD
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
#define KECCAK_USE_BIT_INTERLEAVING
/* #pragma message "Keccak: Compiling at 32 bit, using bit interleaving" */
#endif

#include "pycrypto_common.h"

typedef struct
{
#ifdef KECCAK_USE_BIT_INTERLEAVING
    uint32_t state[50];
#else
    uint64_t state[25];
#endif
    uint8_t  buf[200];
    uint8_t *bufptr;
    uint8_t *bufend;
    uint16_t security;
    uint16_t capacity;
    uint16_t rate;
    uint8_t  squeezing;
    uint8_t  padding;
} keccak_state;

EXPORT_SYM int keccak_init   (keccak_state **state, size_t digest_bytes, uint8_t padding);
EXPORT_SYM int keccak_destroy(keccak_state *state);
EXPORT_SYM int keccak_absorb (keccak_state *state, const uint8_t *buffer, size_t length);
EXPORT_SYM int keccak_copy   (const keccak_state *source, keccak_state *dest);
EXPORT_SYM int keccak_digest (const keccak_state *state, uint8_t *digest, size_t digest_bytes);

#endif /* __KECCAK_H_ */
