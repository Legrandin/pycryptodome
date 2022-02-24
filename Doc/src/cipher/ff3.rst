FF3
===

FF3 `(Format Preserving Encryption)`__ is a a method of encryption which
encrypts a plaintext into a ciphertext while preserving the format of the
plaintext. PyCryptodome implements FF3-1 as outlined in NIST 800-38G NIST_ .

Format Preserving Encryption is useful for legacy systems and other situations
where sensitive data must be protected, but the format and the length must be
retained. Common examples include Social Security Numbers (SSNs) and credit
card numbers.

FF3 uses the AES block cipher under the hood in CBC-MAC mode, and supports
keys lengths of 128, 192, or 256 bits long.

Format Preserving Encryption has a few unique properties which are required
to successfully use the algorithm:

1. **Alphabet**: Alphabets represent the valid characters that can appear in
a plaintext. For SSNs and credit cards, which can contain only digits, the
alphabet would be "0123456789". NIST ACVP defines an alphabet as a minimum of
two characters, and a maximum of 64 (all numbers and upper and lower case
letters, additionally "+" and "/").

2. **Radix**: The radix is simply the length of the alphabet, and represents
the number base. For example, SSNs are decimal digits and are in base 10.

3. **Tweak**: A tweak is a non-secret value that can be used to change part of
the key. Tweaks are necessary in Format Preserving Encryption because the domain
of ciphertexts can be relatively low. FF3-1 tweaks must be 7 bytes in length.
Any information that is available and associated with a plaintext can be used
as a tweak. It's very similar to a salt value in that it doesn't need to be
secret, but should be unique. Tweaks should be used whenever possible to limit
guessing attacks.

FF3-1 example::

    >>> from Crypto.Cipher.FF3 import FF3
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> alphabet = "0123456789"
    >>> radix = len(alphabet)
    >>> key = get_random_bytes(16)
    >>> fpe = FF3(radix, alphabet, key)

You can encrypt a plaintext by passing the plaintext and a tweak to the
encrypt() method::

    >>> tweak = get_random_bytes(7)
    >>> pt = "123456789"
    >>> ct = fpe.encrypt(pt, tweak)
    >>> print(ct)
    930076983

You can decrypt a ciphertext by passing the ciphertext and a tweak to the
decrypt() method:

    >>> pt = fpe.decrypt(ct, tweak)
    >>> print(pt)
    123456789

FPE is deterministic, and the same plaintext and tweak values will provide the
same ciphertext. However, modifying the tweak value will change the associated
ciphertext:

    >>> ct = fpe.encrypt(pt, tweak)
    >>> print(ct)
    930076983
    >>> tweak = get_random_bytes(7)
    >>> ct = fpe.encrypt(pt, tweak)
    >>> print(ct)
    138680525
    >>> pt = fpe.decrypt(ct, tweak)
    >>> print(pt)
    123456789

Note that NIST also defines FF1, which has patent claims and is not implemented
by PyCryptodome.

.. __: https://en.wikipedia.org/wiki/Format-preserving_encryption
.. _NIST: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf

.. automodule:: Crypto.Cipher.FF3
    :members:
