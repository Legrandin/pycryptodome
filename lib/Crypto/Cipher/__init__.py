# -*- coding: utf-8 -*-
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

"""Symmetric- and asymmetric-key encryption algorithms.

Encryption algorithms transform plaintext in some way that
is dependent on a key or key pair, producing ciphertext.

Symmetric algorithms
--------------------

Encryption can easily be reversed, if (and, hopefully, only if)
one knows the same key.
In other words, sender and receiver share the same key.

The symmetric encryption modules here all support the interface described in PEP
272, "API for Block Encryption Algorithms".

If you don't know which algorithm to choose, use AES because it's
standard and has undergone a fair bit of examination.

========================    =======   ========================
Module name                 Type      Description
========================    =======   ========================
`Crypto.Cipher.AES`         Block     Advanced Encryption Standard
`Crypto.Cipher.ARC2`        Block     Alleged RC2
`Crypto.Cipher.ARC4`        Stream    Alleged RC4
`Crypto.Cipher.Blowfish`    Block     Blowfish
`Crypto.Cipher.CAST`        Block     CAST
`Crypto.Cipher.DES`         Block     The Data Encryption Standard.
                                      Very commonly used in the past,
                                      but today its 56-bit keys are too small.
`Crypto.Cipher.DES3`        Block     Triple DES
`Crypto.Cipher.Salsa20`     Stream    Salsa20
`Crypto.Cipher.ChaCha20`    Stream    ChaCha20
========================    =======   ========================


Asymmetric algorithms
---------------------

For asymmetric algorithms, the key to be used for decryption is totally
different and cannot be derived in a feasible way from the key used
for encryption. Put differently, sender and receiver each own one half
of a key pair. The encryption key is often called ``public`` whereas
the decryption key is called ``private``.

==========================    =======================
Module name                   Description
==========================    =======================
`Crypto.Cipher.PKCS1_v1_5`    PKCS#1 v1.5 encryption, based on RSA key pairs
`Crypto.Cipher.PKCS1_OAEP`    PKCS#1 OAEP encryption, based on RSA key pairs
==========================    =======================

:undocumented:  __package__, _AES, _ARC2, _ARC4, _Blowfish
               _CAST, _DES, _DES3, _XOR, _AESNI, _Salsa20
"""

import os

from Crypto.Cipher._mode_ecb import _create_ecb_cipher
from Crypto.Cipher._mode_cbc import _create_cbc_cipher
from Crypto.Cipher._mode_cfb import _create_cfb_cipher
from Crypto.Cipher._mode_ofb import _create_ofb_cipher
from Crypto.Cipher._mode_ctr import _create_ctr_cipher
from Crypto.Cipher._mode_openpgp import _create_openpgp_cipher
from Crypto.Cipher._mode_ccm import _create_ccm_cipher
from Crypto.Cipher._mode_eax import _create_eax_cipher
from Crypto.Cipher._mode_siv import _create_siv_cipher
from Crypto.Cipher._mode_gcm import _create_gcm_cipher
from Crypto.Cipher._mode_ocb import _create_ocb_cipher

_modes = { 1:_create_ecb_cipher,
           2:_create_cbc_cipher,
           3:_create_cfb_cipher,
           5:_create_ofb_cipher,
           6:_create_ctr_cipher,
           7:_create_openpgp_cipher,
           9:_create_eax_cipher
           }

_extra_modes = { 8:_create_ccm_cipher,
                10:_create_siv_cipher,
                11:_create_gcm_cipher,
                12:_create_ocb_cipher
                }

def _create_cipher(factory, key, mode, *args, **kwargs):

    kwargs["key"] = key

    modes = dict(_modes)
    if kwargs.pop("add_aes_modes", False):
        modes.update(_extra_modes)
    if not modes.has_key(mode):
        raise ValueError("Mode not supported")

    if args:
        if mode in (8, 9, 10, 11, 12):
            kwargs["nonce"] = args[0]
        elif mode in (2, 3, 5, 7):
            kwargs["IV"] = args[0]
        elif mode == 1:
            raise TypeError("IV is not meaningful for the ECB mode")

    return modes[mode](factory, **kwargs)
