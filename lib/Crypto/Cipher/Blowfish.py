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

**Use AES, not Blowfish. This module is provided only for legacy purposes.**

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import Blowfish
    >>> from struct import pack
    >>>
    >>> bs = Blowfish.block_size
    >>> key = b'An arbitrarily long key'
    >>> cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    >>> plaintext = b'docendo discimus '
    >>> plen = bs - len(plaintext) % bs
    >>> padding = [plen]*plen
    >>> padding = pack('b'*plen, *padding)
    >>> msg = cipher.iv + cipher.encrypt(plaintext + padding)

.. _Blowfish: http://www.schneier.com/blowfish.html

:undocumented: __package__
"""

import sys

from Crypto.Cipher import _create_cipher
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
        Its length can vary from 5 to 56 bytes.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.

    :Keywords:
      iv : byte string
        (*Only* `MODE_CBC`, `MODE_CFB`, `MODE_OFB`, `MODE_OPENPGP`).

        The initialization vector to use for encryption or decryption.

        For `MODE_OPENPGP`, IV must be 8 bytes long for encryption
        and 10 bytes for decryption (in the latter case, it is
        actually the *encrypted* IV which was prefixed to the ciphertext).

        For all other modes, it must be 8 bytes long.

        If not provided, a random byte string will be generated (you must
        read it back via the ``iv`` attribute).

      nonce : byte string
        (*Only* `MODE_EAX` and `MODE_CTR`).
        A value that must never be reused for any other encryption.

        For `MODE_CTR`, its length must be in the range ``[0..7]``.

        For `MODE_EAX`, there are no restrictions, but it is recommended to
        use at least 16 bytes.

        If not provided for `MODE_EAX`, a 16 byte random string will be used
        (you can read it back via the ``nonce`` attribute).

      mac_len : integer
        (*Only* `MODE_EAX`). Length of the authentication tag, in bytes.
        It must be no larger than 8 (which is the default).

      segment_size : integer
        (*Only* `MODE_CFB`).The number of bits the plaintext and ciphertext
        are segmented in. It must be a multiple of 8.
        If not specified, it will be assumed to be 8.

      initial_value : integer
        (*Only* `MODE_CTR`). The initial value for the counter within
        the counter block. By default it is 0.

    :Return: a Blowfish cipher object, of the applicable mode:

        - CBC_ mode
        - CFB_ mode
        - CTR_ mode
        - EAX_ mode
        - ECB_ mode
        - OFB_ mode
        - OpenPgp_ mode

    .. _CBC: Crypto.Cipher._mode_cbc.CbcMode-class.html
    .. _CFB: Crypto.Cipher._mode_cfb.CfbMode-class.html
    .. _CTR: Crypto.Cipher._mode_ctr.CtrMode-class.html
    .. _EAX: Crypto.Cipher._mode_eax.EaxMode-class.html
    .. _ECB: Crypto.Cipher._mode_ecb.EcbMode-class.html
    .. _OFB: Crypto.Cipher._mode_ofb.OfbMode-class.html
    .. _OpenPgp: Crypto.Cipher._mode_openpgp.OpenPgpMode-class.html
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
key_size = xrange(5, 56 + 1)
