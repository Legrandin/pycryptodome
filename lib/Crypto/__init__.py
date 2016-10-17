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

"""Python Cryptography Toolkit

A collection of cryptographic modules implementing various algorithms
and protocols.

Subpackages:

Crypto.Cipher
 Secret-key (AES, TDES, Salsa20, ChaCha20, CAST, Blowfish, ARC4) and public-key encryption (RSA PKCS#1) algorithms
Crypto.Hash
 Hashing algorithms (SHA-1, SHA-2, SHA-3, BLAKE2, HMAC, MD5)
Crypto.IO
 Encodings useful for cryptographic data (PEM, PKCS#8)
Crypto.Protocol
 Cryptographic protocols (key derivation functions, Shamir's Secret Sharing scheme)
Crypto.PublicKey
 Public-key generation, import, export (RSA, DSA, ECC)
Crypto.Signature
 Public-key signature algorithms (RSA PKCS#1, DSA, ECDSA)
Crypto.Util
 Various useful modules and functions (padding, ASN.1, XOR)
"""

__all__ = ['Cipher', 'Hash', 'Protocol', 'PublicKey', 'Util', 'Signature',
           'IO', 'Math']

version_info = (3, 4, 3)
