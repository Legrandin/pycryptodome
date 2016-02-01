# -*- coding: utf-8 -*-
#
#  Cipher/ARC2.py : ARC2.py
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
"""RC2 symmetric cipher

RC2_ (Rivest's Cipher version 2)  is a symmetric block cipher designed
by Ron Rivest in 1987. The cipher started as a proprietary design,
that was reverse engineered and anonymously posted on Usenet in 1996.
For this reason, the algorithm was first called *Alleged* RC2 (ARC2),
since the company that owned RC2 (RSA Data Inc.) did not confirm whether
the details leaked into public domain were really correct.

The company eventually published its full specification in RFC2268_.

RC2 has a fixed data block size of 8 bytes. Length of its keys can vary from
8 to 128 bits. One particular property of RC2 is that the actual
cryptographic strength of the key (*effective key length*) can be reduced
via a parameter.

Even though RC2 is not cryptographically broken, it has not been analyzed as
thoroughly as AES, which is also faster than RC2.

**Use AES, not ARC2. This module is only provided for legacy purposes.**

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import ARC2
    >>>
    >>> key = b'Sixteen byte key'
    >>> cipher = ARC2.new(key, ARC2.MODE_CFB)
    >>> msg = cipher.iv + cipher.encrypt(b'Attack at dawn')

.. _RC2: http://en.wikipedia.org/wiki/RC2
.. _RFC2268: http://tools.ietf.org/html/rfc2268

:undocumented: __package__
"""

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util.py3compat import byte_string
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  c_size_t, expect_byte_string)

_raw_arc2_lib = load_pycryptodome_raw_lib(
                        "Crypto.Cipher._raw_arc2",
                        """
                        int ARC2_start_operation(const uint8_t key[],
                                                 size_t key_len,
                                                 size_t effective_key_len,
                                                 void **pResult);
                        int ARC2_encrypt(const void *state,
                                         const uint8_t *in,
                                         uint8_t *out,
                                         size_t data_len);
                        int ARC2_decrypt(const void *state,
                                         const uint8_t *in,
                                         uint8_t *out,
                                         size_t data_len);
                        int ARC2_stop_operation(void *state);
                        """
                        )


def _create_base_cipher(dict_parameters):
    """This method instantiates and returns a handle to a low-level
    base cipher. It will absorb named parameters in the process."""

    try:
        key = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")

    effective_keylen = dict_parameters.pop("effective_keylen", 1024)

    expect_byte_string(key)

    if len(key) not in key_size:
        raise ValueError("Incorrect ARC2 key length (%d bytes)" % len(key))

    if not (40 < effective_keylen <= 1024):
        raise ValueError("'effective_key_len' must be no larger than 1024 "
                         "(not %d)" % effective_keylen)

    start_operation = _raw_arc2_lib.ARC2_start_operation
    stop_operation = _raw_arc2_lib.ARC2_stop_operation

    cipher = VoidPointer()
    result = start_operation(key,
                             c_size_t(len(key)),
                             c_size_t(effective_keylen),
                             cipher.address_of())
    if result:
        raise ValueError("Error %X while instantiating the ARC2 cipher"
                         % result)

    return SmartPointer(cipher.get(), stop_operation)


def new(key, mode, *args, **kwargs):
    """Create a new RC2 cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        Its length can vary from 5 to 128 bytes.

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

        If not provided, a random byte string will be generated (you
        must read it back via the ``iv`` attribute of the cipher).

      nonce : byte string
        (*Only* `MODE_EAX` and `MODE_CTR`).
        A value that must never be reused for any other encryption done with
        this key.

        For `MODE_CTR`, its length must be in the range ``[0..7]``.

        For `MODE_EAX`, there are no restrictions, but it is recommended to
        use at least 16 bytes.

        If not provided for `MODE_EAX`, a random byte string will be
        generated (you must read it back via the ``nonce`` attribute
        of the cipher).

      mac_len : integer
        (*Only* `MODE_EAX`). Length of the authentication tag, in bytes.
        It must be no larger than 8 (which is the default).

      segment_size : integer
        (*Only* `MODE_CFB`).
        The number of **bits** the plaintext and ciphertext are segmented in.
        It must be a multiple of 8. If not specified,
        it will be assumed to be 8.

      initial_value : integer
        (*Only* `MODE_CTR`). The initial value for the counter within
        the counter block. By default it is 0.

      effective_keylen : integer
        Maximum cryptographic strength of the key, in **bits**.
        It can vary from 40 to 1024. The default value is 1024.

    :Return: an RC2 cipher object, of the applicable mode:

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
key_size = xrange(5, 128 + 1)
