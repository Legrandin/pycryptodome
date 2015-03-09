# -*- coding: utf-8 -*-
#
#  Cipher/Blowfish.py : Blowfish
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
"""Blowfish symmetric cipher

Blowfish_ is a symmetric block cipher designed by Bruce Schneier.

It has a fixed data block size of 8 bytes and its keys can vary in length
from 32 to 448 bits (4 to 56 bytes).

Blowfish is deemed secure and it is fast. However, its keys should be chosen
to be big enough to withstand a brute force attack (e.g. at least 16 bytes).

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import Blowfish
    >>> from Crypto import Random
    >>> from struct import pack
    >>>
    >>> bs = Blowfish.block_size
    >>> key = b'An arbitrarily long key'
    >>> iv = Random.new().read(bs)
    >>> cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    >>> plaintext = b'docendo discimus '
    >>> plen = bs - len(plaintext) % bs
    >>> padding = [plen]*plen
    >>> padding = pack('b'*plen, *padding)
    >>> msg = iv + cipher.encrypt(plaintext + padding)

.. _Blowfish: http://www.schneier.com/blowfish.html

:undocumented: __package__
"""

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util.py3compat import byte_string
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer, c_size_t,
                                  expect_byte_string)

_raw_blowfish_lib = load_pycryptodome_raw_lib(
        "Crypto.Cipher._raw_blowfish",
        """
        int Blowfish_start_operation(const uint8_t key[],
                                     size_t key_len,
                                     void **pResult);
        int Blowfish_encrypt(const void *state,
                             const uint8_t *in,
                             uint8_t *out,
                             size_t data_len);
        int Blowfish_decrypt(const void *state,
                             const uint8_t *in,
                             uint8_t *out,
                             size_t data_len);
        int Blowfish_stop_operation(void *state);
        """
        )


def _create_base_cipher(dict_parameters):
    """This method instantiates and returns a smart pointer to
    a low-level base cipher. It will absorb named parameters in
    the process."""

    try:
        key = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")

    expect_byte_string(key)

    if len(key) not in key_size:
        raise ValueError("Incorrect Blowfish key length (%d bytes)" % len(key))

    start_operation = _raw_blowfish_lib.Blowfish_start_operation
    stop_operation = _raw_blowfish_lib.Blowfish_stop_operation

    void_p = VoidPointer()
    result = start_operation(key, c_size_t(len(key)), void_p.address_of())
    if result:
        raise ValueError("Error %X while instantiating the Blowfish cipher"
                         % result)
    return SmartPointer(void_p.get(), stop_operation)


def new(key, mode, *args, **kwargs):
    """Create a new Blowfish cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        Its length can vary from 4 to 56 bytes.
      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
    :Keywords:
      IV : byte string
        (*Only* `MODE_CBC`, `MODE_CFB`, `MODE_OFB`, `MODE_OPENPGP`).

        The initialization vector to use for encryption or decryption.

        It is ignored for `MODE_ECB` and `MODE_CTR`.

        For `MODE_OPENPGP`, IV must be `block_size` bytes long for encryption
        and `block_size` +2 bytes for decryption (in the latter case, it is
        actually the *encrypted* IV which was prefixed to the ciphertext).
        It is mandatory.

        For all other modes, it must be 8 bytes long.
      nonce : byte string
        (*Only* `MODE_EAX`).
        A mandatory value that must never be reused for any other encryption.
        There are no restrictions on its length, but it is recommended to
        use at least 16 bytes.
      counter : callable
        (*Only* `MODE_CTR`). A stateful function that returns the next
        *counter block*, which is a byte string of `block_size` bytes.
        For better performance, use `Crypto.Util.Counter`.
      mac_len : integer
        (*Only* `MODE_EAX`). Length of the MAC, in bytes.
        It must be no larger than 8 (which is the default).
      segment_size : integer
        (*Only* `MODE_CFB`).The number of bits the plaintext and ciphertext
        are segmented in.
        It must be a multiple of 8. If 0 or not specified,
        it will be assumed to be 8.

    :Return: a Blowfish cipher object, of the applicable mode.
    """

    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

#: Electronic Code Book (ECB). See `Crypto.Cipher._mode_ecb.EcbMode`.
MODE_ECB = 1
#: Cipher-Block Chaining (CBC). See `Crypto.Cipher._mode_cbc.CbcMode`.
MODE_CBC = 2
#: Cipher FeedBack (CFB). See `Crypto.Cipher._mode_cfb.CfbMode`.
MODE_CFB = 3
#: Output FeedBack (OFB). See `Crypto.Cipher._mode_ofb.OfbMode`.
MODE_OFB = 5
#: CounTer Mode (CTR). See `Crypto.Cipher._mode_ctr.CtrMode`.
MODE_CTR = 6
#: OpenPGP Mode. See `Crypto.Cipher._mode_openpgp.OpenPgpMode`.
MODE_OPENPGP = 7
#: EAX Mode. See `Crypto.Cipher._mode_eax.EaxMode`.
MODE_EAX = 9

#: Size of a data block (in bytes)
block_size = 8
#: Size of a key (in bytes)
key_size = xrange(4, 56 + 1)
