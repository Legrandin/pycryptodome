# -*- coding: utf-8 -*-
#
#  Cipher/DES3.py : DES3
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
"""Triple DES symmetric cipher

`Triple DES`__ (or TDES or TDEA or 3DES) is a symmetric block cipher
standardized by NIST_. It has a fixed data block size of 8 bytes.

TDES consists of the concatenation of 3 simple Single `DES` ciphers
(encryption - decryption - encryption), where each stage uses an
indipendent sub-key.

A TDES key is therefore 24 (8+8+8) bytes long. However, like Single DES,
only 7 out of 8 bits are actually used: the remaining ones are parity
bits (which practically all TDES implementations ignore).
Theoreticaly, Triple DES achieves up to 112 bits of effective security.

Triple DES can also operate with a 16 bytes key (Option 2, also termed 2TDES),
in which case subkey *K1* equals subkey *K2*. The effective security
is as low as `90 bits`_.

Thi implementation checks and enforces the condition *K1 != K2 != K3*
(Option 3), as it degrades Triple DES to Single DES.

*Use AES, not TDES. This module is provided for legacy purposes only.**

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import DES3
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> # When generating a Triple DES key you must check that
    >>> # subkey1 != subkey2 and subkey2 != subkey3
    >>> while True:
    >>>     try:
    >>>         key = DES3.adjust_key_parity(get_random_bytes(24))
    >>>         break
    >>>     except ValueError
    >>>         pass
    >>>
    >>> cipher = DES3.new(key, DES3.MODE_CFB)
    >>> plaintext = b'We are no longer the knights who say ni!'
    >>> msg = cipher.nonce + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Triple_DES
.. _NIST: http://csrc.nist.gov/publications/nistpubs/800-67-Rev1/SP-800-67-Rev1.pdf
.. _90 bits: http://people.scs.carleton.ca/~paulv/papers/Euro90.pdf

:undocumented: __package__
"""

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util.py3compat import byte_string, b, bchr, bord
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  c_size_t, expect_byte_string)

_raw_des3_lib = load_pycryptodome_raw_lib(
                    "Crypto.Cipher._raw_des3",
                    """
                    int DES3_start_operation(const uint8_t key[],
                                             size_t key_len,
                                             void **pResult);
                    int DES3_encrypt(const void *state,
                                     const uint8_t *in,
                                     uint8_t *out,
                                     size_t data_len);
                    int DES3_decrypt(const void *state,
                                     const uint8_t *in,
                                     uint8_t *out,
                                     size_t data_len);
                    int DES3_stop_operation(void *state);
                    """)


def adjust_key_parity(key_in):
    """Return the TDES key with parity bits correctly set"""

    def parity_byte(key_byte):
        parity = 1
        for i in xrange(1, 8):
            parity ^= (key_byte >> i) & 1
        return (key_byte & 0xFE) | parity

    if len(key_in) not in key_size:
        raise ValueError("Not a valid TDES key")

    key_out = b("").join([ bchr(parity_byte(bord(x)) )for x in key_in ])

    if key_out[:8] == key_out[8:16] or key_out[-16:-8] == key_out[-8:]:
        raise ValueError("Triple DES key degenerates to single DES")

    return key_out


def _create_base_cipher(dict_parameters):
    """This method instantiates and returns a handle to a low-level base cipher.
    It will absorb named parameters in the process."""

    try:
        key_in = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")

    key = adjust_key_parity(key_in)

    start_operation = _raw_des3_lib.DES3_start_operation
    stop_operation = _raw_des3_lib.DES3_stop_operation

    cipher = VoidPointer()
    result = start_operation(key,
                             c_size_t(len(key)),
                             cipher.address_of())
    if result:
        raise ValueError("Error %X while instantiating the TDES cipher"
                         % result)
    return SmartPointer(cipher.get(), stop_operation)


def new(key, mode, *args, **kwargs):
    """Create a new TDES cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        It must be 16 or 24 bytes long. The parity bits will be ignored.
        The condition K1 != K2 != K3 must hold.

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

        If not provided, a random byte string will be generated (you can read
        it back via the ``iv`` attribute).

      nonce : byte string
        (*Only* `MODE_EAX` and `MODE_CTR`)
        A value that must never be reused for any other encryption.

        For `MODE_CTR`, its length must be in the range ``[0..7]``.

        For `MODE_EAX`, there are no restrictions, but it is recommended to
        use at least 16 bytes.

        If not provided for `MODE_EAX`, a random 16 byte string is generated
        (you can read it back via the ``nonce`` attribute).

      mac_len : integer
        (*Only* `MODE_EAX`). Length of the authentication tag, in bytes.
        It must be no larger than 8 (which is the default).

      segment_size : integer
        (*Only* `MODE_CFB`).The number of **bits** the plaintext and ciphertext
        are segmented in. It must be a multiple of 8.
        If not specified, it will be assumed to be 8.

      initial_value : integer
        (*Only* `MODE_CTR`). The initial value for the counter within
        the counter block. By default it is 0.

    :Attention: it is important that all 8 byte subkeys are different,
      otherwise TDES would degrade to single `DES`.

    :Raise ValueError:
      when the key degrades to Single DES.

    :Return: a DES cipher object, of the applicable mode:

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
key_size = (16, 24)
