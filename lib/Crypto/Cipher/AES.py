# -*- coding: utf-8 -*-
#
#  Cipher/AES.py : AES
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
"""AES symmetric cipher

AES `(Advanced Encryption Standard)`__ is a symmetric block cipher standardized
by NIST_ . It has a fixed data block size of 16 bytes.
Its keys can be 128, 192, or 256 bits long.

AES is very fast and secure, and it is the de facto standard for symmetric
encryption.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = b'Sixteen byte key'
    >>> iv = get_random_bytes(16)
    >>> cipher = AES.new(key, AES.MODE_CFB, iv)
    >>> msg = iv + cipher.encrypt(b'Attack at dawn')

A more complicated example is based on CCM, (see `MODE_CCM`) an `AEAD`_ mode
that provides both confidentiality and authentication for a message.

It optionally allows the header of the message to remain in the clear,
whilst still being authenticated. The encryption is done as follows:

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>>
    >>> hdr = b'To your eyes only'
    >>> plaintext = b'Attack at dawn'
    >>> key = b'Sixteen byte key'
    >>> nonce = get_random_bytes(11)
    >>> cipher = AES.new(key, AES.MODE_CCM, nonce)
    >>> cipher.update(hdr)
    >>> msg = nonce, hdr, cipher.encrypt(plaintext), cipher.digest()

We assume that the tuple ``msg`` is transmitted to the receiver:

    >>> nonce, hdr, ciphertext, mac = msg
    >>> key = b'Sixteen byte key'
    >>> cipher = AES.new(key, AES.MODE_CCM, nonce)
    >>> cipher.update(hdr)
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> try:
    >>>     cipher.verify(mac)
    >>>     print "The message is authentic: hdr=%s, pt=%s" % (hdr, plaintext)
    >>> except ValueError:
    >>>     print "Key incorrect or message corrupted"

.. __: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _NIST: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
"""

import sys

from Crypto.Cipher import _create_cipher
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  c_size_t, expect_byte_string)


_raw_cpuid_lib = load_pycryptodome_raw_lib("Crypto.Util._cpuid",
                                           "int have_aes_ni(void);")

cproto = """
        int AES_start_operation(const uint8_t key[],
                                size_t key_len,
                                void **pResult);
        int AES_encrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_decrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_stop_operation(void *state);
        """


_raw_aes_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes",
                                         cproto)

_raw_aesni_lib = None
try:
    if _raw_cpuid_lib.have_aes_ni() == 1:
        _raw_aesni_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aesni",
                                                   cproto.replace("AES",
                                                                  "AESNI"))
except OSError:
    pass


def _create_base_cipher(dict_parameters):
    """This method instantiates and returns a handle to a low-level
    base cipher. It will absorb named parameters in the process."""

    use_aesni = dict_parameters.pop("use_aesni", True)

    try:
        key = dict_parameters.pop("key")
    except KeyError:
        raise TypeError("Missing 'key' parameter")

    expect_byte_string(key)

    if len(key) not in key_size:
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key))

    if use_aesni and _raw_aesni_lib:
        start_operation = _raw_aesni_lib.AESNI_start_operation
        stop_operation = _raw_aesni_lib.AESNI_stop_operation
    else:
        start_operation = _raw_aes_lib.AES_start_operation
        stop_operation = _raw_aes_lib.AES_stop_operation

    cipher = VoidPointer()
    result = start_operation(key,
                             c_size_t(len(key)),
                             cipher.address_of())
    if result:
        raise ValueError("Error %X while instantiating the AES cipher"
                         % result)
    return SmartPointer(cipher.get(), stop_operation)


def new(key, mode, *args, **kwargs):
    """Create a new AES cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        It must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*)
        bytes long.

        Only in `MODE_SIV`, it needs to be 32, 48, or 64 bytes long.
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

        For all other modes, it must be 16 bytes long.
      nonce : byte string
        (*Only* `MODE_CCM`, `MODE_EAX`, `MODE_GCM`, `MODE_SIV`, `MODE_OCB`).

        A mandatory value that must never be reused for any other encryption.

        For `MODE_CCM`, its length must be in the range ``[7..13]``.
        11 or 12 bytes are reasonable values in general. Bear in
        mind that with CCM there is a trade-off between nonce length and
        maximum message size.

        For `MODE_OCB`, its length must be in the range ``[1..15]``.
        It is recommended to use 15 bytes.

        For the other modes, there are no restrictions on its length,
        but it is recommended to use at least 16 bytes.
      counter : callable
        (*Only* `MODE_CTR`). A stateful function that returns the next
        *counter block*, which is a byte string of `block_size` bytes.
        For better performance, use `Crypto.Util.Counter`.
      segment_size : integer
        (*Only* `MODE_CFB`).The number of bits the plaintext and ciphertext
        are segmented in.
        It must be a multiple of 8. If 0 or not specified,
        it will be assumed to be 8.
      mac_len : integer
        (*Only* `MODE_CCM`). Length of the MAC, in bytes. It must be even
        and in the range ``[4..16]``. The default is 16.

        (*Only* `MODE_EAX`, `MODE_GCM`, `MODE_OCB`). Length of the MAC, in bytes.
        It must be no larger than 16 bytes (which is the default).
      msg_len : integer
        (*Only* `MODE_CCM`). Length of the message to (de)cipher.
        If not specified, ``encrypt`` or ``decrypt`` may only be called once.
      assoc_len : integer
        (*Only* `MODE_CCM`). Length of the associated data.
        If not specified, all data is internally buffered.
      use_aesni : boolean
        Use AES-NI if available.

    :Return: an AES object, of the applicable mode.
    """

    kwargs["add_aes_modes"] = True
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
#: Counter with CBC-MAC (CCM) Mode. See `Crypto.Cipher._mode_ccm.CcmMode`.
MODE_CCM = 8
#: EAX Mode. See `Crypto.Cipher._mode_eax.EaxMode`.
MODE_EAX = 9
#: Syntethic Initialization Vector (SIV). See `Crypto.Cipher._mode_siv.SivMode`.
MODE_SIV = 10
#: Galois Counter Mode (GCM). See `Crypto.Cipher._mode_gcm.GcmMode`.
MODE_GCM = 11
#: Offset Code Book (OCB). See `Crypto.Cipher._mode_ocb.OcbMode`.
MODE_OCB = 12

#: Size of a data block (in bytes)
block_size = 16
#: Size of a key (in bytes)
key_size = (16, 24, 32)
