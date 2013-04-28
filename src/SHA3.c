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
              sources=["src/sha3.c", "src/keccak.c"],
              define_macros=[('MODULE_NAME', '_SHA3_nnn'),
                ('DIGEST_SIZE', '%d' % (nnn/8))]),

*/
#include "config.h"

#define CAPACITY (2*(DIGEST_SIZE))
#define BLOCK_SIZE (200-CAPACITY)

static char MODULE__doc__[] =
#if   (MODULE_NAME == SHA3_224)
    "SHA3-224 cryptographic hash algorithm.\n"
    "\n"
    "SHA3-224 belongs to the SHA-3 family of cryptographic hashes.\n"
    "It produces the 224 bit digest of a message.\n"
    "  \n"
    "    >>> from Crypto.Hash import SHA3_224\n"
    "    >>>\n"
    "    >>> h = SHA3_224.new()\n"
#elif (MODULE_NAME == SHA3_256)
    "SHA3-256 cryptographic hash algorithm.\n"
    "\n"
    "SHA3-256 belongs to the SHA-3 family of cryptographic hashes.\n"
    "It produces the 256 bit digest of a message.\n"
    "  \n"
    "    >>> from Crypto.Hash import SHA3_256\n"
    "    >>>\n"
    "    >>> h = SHA3_256.new()\n"
#elif (MODULE_NAME == SHA3_384)
    "SHA3-384 cryptographic hash algorithm.\n"
    "\n"
    "SHA3-384 belongs to the SHA-3 family of cryptographic hashes.\n"
    "It produces the 384 bit digest of a message.\n"
    "  \n"
    "    >>> from Crypto.Hash import SHA3_384\n"
    "    >>>\n"
    "    >>> h = SHA3_384.new()\n"
#elif (MODULE_NAME == SHA3_512)
    "SHA3-512 cryptographic hash algorithm.\n"
    "\n"
    "SHA3-512 belongs to the SHA-3 family of cryptographic hashes.\n"
    "It produces the 512 bit digest of a message.\n"
    "  \n"
    "    >>> from Crypto.Hash import SHA3_512\n"
    "    >>>\n"
    "    >>> h = SHA3_512.new()\n"
#endif
"    >>> h.update(b'Hello')\n"
"    >>> print h.hexdigest()\n"
"\n"
"*SHA* stands for Secure Hash Algorithm.\n"
"\n"
".. Algorithm specifications: http://keccak.noekeon.org/\n"
".. As of April 2013, NIST has not yet updated Secure Hash Standard\n"
".. (SHS) for SHA-3. This module is subject to change once the final\n"
".. standard is published.";

#include "pycrypto_common.h"
#include "keccak.h"

typedef keccak_state hash_state;

#ifdef _MSC_VER
#define INLINE __inline
#else
#define INLINE inline
#endif

INLINE void
hash_init (hash_state *self)
{   
    keccak_init (self, DIGEST_SIZE, KECCAK_INIT_SECURITY);
}

INLINE void
hash_update (hash_state *self, unsigned char *buffer, int length)
{
    keccak_absorb (self, buffer, length);
}

INLINE void
hash_copy (hash_state *source, hash_state *dest)
{
    keccak_copy (source, dest);
}

#undef INLINE

PyObject
*hash_digest (hash_state *self)
{
    hash_state tmp;
    char buffer[DIGEST_SIZE];
    
    hash_copy (self, &tmp);
    keccak_squeeze (&tmp, buffer, DIGEST_SIZE);
    
	return PyBytes_FromStringAndSize (buffer, DIGEST_SIZE);
}

#include "hash_template.c"

/* vim:set ts=4 sw=4 sts=4 expandtab: */
