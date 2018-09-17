# -*- coding: utf-8 -*-
#
# Hash/Poly1305_AES.py - Implements the Poly1305-AES MAC
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

from Crypto.Cipher import AES
from Crypto.Hash._Poly1305 import Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Util.py3compat import _copy_bytes

class Poly1305_AES(Poly1305):

    def __init__(self, key, nonce, data):

        r = key[:16]
        s = AES.new(AES.MODE_ECB, key[16:]).encrypt(nonce)
        self._nonce = _copy_bytes(0, 16, nonce)

        Poly1305.__init__(self, r, s, data)

    @property
    def nonce(self):
        return self._nonce


def new(**kwargs):
    """Create a new Poly1305-AES MAC object.

    Args:
        key (bytes/bytearray/memoryview):
            The 32-byte key for the Poly1305-AES object.
        nonce (bytes/bytearray/memoryview):
            Optional. The non-repeatable value to use for the MAC of this
            message. It must be 16 bytes long.
            If not passed, a random nonce is created.
        msg (bytes/bytearray/memoryview):
            Optional. The very first chunk of the message to authenticate.
            It is equivalent to an early call to ``update()``.

    Returns:
        A :class:`Poly1305_AES` object
    """

    aes_key = kwargs.pop("key", None)
    if aes_key is None:
        raise TypeError("Parameter 'key' not found")

    nonce = kwargs.pop("nonce", None)
    msg = kwargs.pop("msg", None)
    
    if nonce is None:
        nonce = get_random_bytes(16)

    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))
    
    if len(key) != 32:
        raise ValueError("Poly1305-AES key must be 32 bytes long")
    
    if len(nonce) != 16:
        raise ValueError("Poly1305-AES nonce must be 16 bytes long")
    
    return Poly1305_AES(key, nonce, msg)
