# -*- coding: ascii -*-
#
#  Util/Counter.py : Fast counter for use with CTR-mode ciphers
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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
"""Fast counter functions for CTR cipher modes.

CTR is a chaining mode for symmetric block encryption or decryption.
Messages are divideded into blocks, and the cipher operation takes
place on each block using the secret key and a unique *counter block*.

The most straightforward way to fulfil the uniqueness property is
to start with an initial, random *counter block* value, and increment it as
the next block is processed.

The block ciphers from `Crypto.Cipher` (when configured in *MODE_CTR* mode)
invoke a callable object (the *counter* parameter) to get the next *counter block*.
Unfortunately, the Python calling protocol leads to major performance degradations.

The counter functions instantiated by this module will be invoked directly
by the ciphers in `Crypto.Cipher`. The fact that the Python layer is bypassed
lead to more efficient (and faster) execution of CTR cipher modes.

An example of usage is the following:

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Util import Counter
    >>> from Crypto import Random
    >>>
    >>> nonce = Random.get_random_bytes(8)
    >>> ctr = Counter.new(64, nonce)
    >>> key = b'AES-128 symm key'
    >>> plaintext = b'X'*1000000
    >>> cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    >>> ciphertext = cipher.encrypt(plaintext)

"""

from Crypto.Util.py3compat import *

def new(nbits, prefix=b(""), suffix=b(""), initial_value=1, little_endian=False, allow_wraparound=False):
    """Create a stateful counter block function suitable for CTR encryption modes.

    Each call to the function returns the next counter block.
    Each counter block is made up by three parts::

      prefix || counter value || postfix

    The counter value is incremented by 1 at each call.

    :Parameters:
      nbits : integer
        Length of the desired counter value, in bits. It must be a multiple of 8.
      prefix : byte string
        The constant prefix of the counter block. By default, no prefix is
        used.
      suffix : byte string
        The constant postfix of the counter block. By default, no suffix is
        used.
      initial_value : integer
        The initial value of the counter. Default value is 1.
      little_endian : boolean
        If *True*, the counter number will be encoded in little endian format.
        If *False* (default), in big endian format.
      allow_wraparound : boolean
        This parameter is ignored.
    :Returns:
      An object that can be passed with the 'counter' parameter to a CTR mode
      cipher.

    It must hold that ``len(prefix) + nbits//8 + len(suffix)`` matches the
    block size of the underlying block cipher.
    """

    if (nbits % 8) != 0:
        raise ValueError("'nbits' must be a multiple of 8")

    # Ignore wraparound
    return {"counter_len": nbits // 8,
            "prefix": prefix,
            "suffix": suffix,
            "initial_value": initial_value,
            "little_endian": little_endian
            }
