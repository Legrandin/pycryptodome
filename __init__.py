
"""Python Cryptography Toolkit

A collection of cryptographic modules implementing various algorithms
and protocols.

Subpackages:
Crypto.Cipher             Secret-key encryption algorithms (AES, DES, ARC4)
Crypto.Hash               Hashing algorithms (MD5, SHA, HMAC)
Crypto.Protocol           Cryptographic protocols (Chaffing, all-or-nothing
                          transform).   This package does not contain any
                          network protocols.
Crypto.PublicKey          Public-key encryption and signature algorithms
                          (RSA, DSA)
Crypto.Util               Various useful modules and functions (long-to-string
                          conversion, random number generation, number
                          theoretic functions)
"""

__all__ = ['Cipher', 'Hash', 'Protocol', 'Util']

__version__ = '1.9a5'
__revision__ = "$Id: __init__.py,v 1.8 2002-09-05 11:27:11 akuchling Exp $"


