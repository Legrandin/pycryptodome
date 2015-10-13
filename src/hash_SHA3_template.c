/*
 * Module implementing a generic SHA-3 digest function (FIPS 202).
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

FAKE_INIT(MODULE_NAME)

#include "keccak.c"

#define FUNC_NAME(pf) _PASTE2(MODULE_NAME, pf)

typedef keccak_state hash_state;

EXPORT_SYM int FUNC_NAME(_init) (hash_state **shaState)
{   
    hash_state *hs;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    *shaState = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;

    keccak_init (hs, DIGEST_SIZE, 0x06);
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
    keccak_absorb (hs, buf, len);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_copy)(const hash_state *src, hash_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    dst->bufptr = dst->buf + (src->bufptr - src->buf);
    dst->bufend = dst->buf + (src->bufend - src->buf);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_digest) (const hash_state *shaState, uint8_t digest[DIGEST_SIZE])
{
    hash_state tmp;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    FUNC_NAME(_copy)(shaState, &tmp);
    keccak_squeeze (&tmp, digest, DIGEST_SIZE);
    return 0;
}
