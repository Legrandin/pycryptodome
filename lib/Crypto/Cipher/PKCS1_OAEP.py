#
#  Cipher/PKCS1_OAEP.py : PKCS#1 OAEP
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""
Legacy module for PKCS#1 OAEP encryption.

Use :mod:`Crypto.Cipher.oaep` instead, which requires the hash function
to be specified explicitly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Optional

import Crypto.Hash.SHA1
from Crypto.Cipher import oaep
from Crypto.Cipher.oaep import Buffer, HashLike, PKCS1OAEP_Cipher

if TYPE_CHECKING:
    from Crypto.PublicKey.RSA import RsaKey


def new(
    key: RsaKey,
    hashAlgo: Optional[HashLike] = None,
    mgfunc: Optional[Callable[[bytes, int], bytes]] = None,
    label: Buffer = b"",
    randfunc: Optional[Callable[[int], bytes]] = None,
) -> PKCS1OAEP_Cipher:
    """Return a cipher object :class:`Crypto.Cipher.oaep.PKCS1OAEP_Cipher`
       that can be used to perform PKCS#1 OAEP encryption or decryption.

    It is the same as :func:`Crypto.Cipher.oaep.new`,
    except that ``hashAlgo`` can be omitted.

    :param key:
      The key object to use to encrypt or decrypt the message.
      Decryption is only possible with a private RSA key.
    :type key: RSA key object

    :param hashAlgo:
      The hash function to use. This can be a module under `Crypto.Hash`
      or an existing hash object created from any of such modules.
      If not specified, `Crypto.Hash.SHA1` is used, matching the RSAES-OAEP
      default defined in RFC8017. New protocols should use SHA-256 or a stronger
      hash function.
    :type hashAlgo: hash object

    :param mgfunc:
      A mask generation function that accepts two parameters: a string to
      use as seed, and the lenth of the mask to generate, in bytes.
      If not specified, the standard MGF1 consistent with ``hashAlgo`` is used (a safe choice).
    :type mgfunc: callable

    :param label:
      A label to apply to this particular encryption. If not specified,
      an empty string is used. Specifying a label does not improve
      security.
    :type label: bytes/bytearray/memoryview

    :param randfunc:
      A function that returns random bytes.
      The default is `Random.get_random_bytes`.
    :type randfunc: callable
    """

    if hashAlgo is None:
        hashAlgo = Crypto.Hash.SHA1
    return oaep.new(key, hashAlgo, mgfunc, label, randfunc)
