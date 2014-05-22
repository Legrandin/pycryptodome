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

#define CAPACITY (2*(DIGEST_SIZE))
#define BLOCK_SIZE (200-CAPACITY)
#define NO_MERKLE_DAMGARD

#define _STR(x) #x
#define _XSTR(x) _STR(x)

static char MODULE__doc__[] =
    HASH_NAME " cryptographic hash algorithm.\n"
    "\n"
    HASH_NAME " belongs to the SHA-3 family of cryptographic hashes, as specified\n"
    "in `FIPS 202`__ (currently in draft stage).\n"
    "The hash function produces the " _XSTR(DIGEST_SIZE_BITS)  " bit digest of a message.\n"
    "  \n"
    "    >>> from Crypto.Hash import SHA3_" _XSTR(DIGEST_SIZE_BITS)  "\n"
    "    >>>\n"
    "    >>> h_obj = SHA3_" _XSTR(DIGEST_SIZE_BITS)  ".new()\n"
    "    >>> h_obj.update(b'Some data')\n"
    "    >>> print h_obj.hexdigest()\n"
    "\n"
    ".. __: http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf\n"
    ;

#include "pycrypto_common.h"
#include "keccak.c"

typedef keccak_state hash_state;

static void
hash_init (hash_state *self)
{   
    keccak_init (self, DIGEST_SIZE, KECCAK_INIT_SECURITY);
}

static void
hash_update (hash_state *self, unsigned char *buffer, int length)
{
    keccak_absorb (self, buffer, length);
}

static void
hash_copy (hash_state *source, hash_state *dest)
{
    keccak_copy (source, dest);
}

static PyObject
*hash_digest (hash_state *self)
{
    hash_state tmp;
    unsigned char buffer[DIGEST_SIZE];
    
    hash_copy (self, &tmp);
    keccak_squeeze (&tmp, buffer, DIGEST_SIZE);
    
    return PyBytes_FromStringAndSize ((char*)buffer, DIGEST_SIZE);
}

#include "hash_template.c"
