# ===================================================================
#
# Copyright (c) 2022, Joshua Holt <joshholt@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

from __future__ import absolute_import

import math

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class FF3:
    """Implementation of the FF3-1 algorithm, as outlined by NIST 800-38G
    (https://csrc.nist.gov/publications/detail/sp/800-38g/rev-1/draft)

    The major changes for FF3-1 is the modification of the tweak value to
    prevent plaintext recovery and increases in the domain size:
    (https://eprint.iacr.org/2017/521.pdf)

    NIST ACVP (https://pages.nist.gov/ACVP/draft-celi-acvp-symmetric.html)
    effectively requires an alphabet limited to 64 alphanumeric characters.
    This implementation is limited to the NIST ACVP parameters.
    """

    def __init__(self, radix, alphabet, key):
        """Initializes the FF3 encryption object. Each object is limited to the
        same key, radix, and alphabet.

        :Parameters:
          radix : The number base in use for the group
          alphabet: Characters representing the alphabet in use for the group.
          key : The AES 128, 192, or 256 bit key to use for operations
        """
        self.radix = radix
        if (self.radix < 2) or (self.radix > 64):
            raise RadixOutOfRangeError('Radix must be between 2 and 64')
        self.alphabet = alphabet
        if (len(self.alphabet) < 2) or (len(self.alphabet) > 64):
            raise AlphabetOutOfRangeError("Alphabet range between 2 and 64")
        # TODO: Need a stronger check here as a subfunction
        if not (self.alphabet.isalnum()):
            if "+/" not in self.alphabet:
                raise AlphabetValueError("Alphabets must contain numbers \
                    and upper and lower case letters, '+ and '/)")
        if len(self.alphabet) != len(set(self.alphabet)):
            raise AlphabetValueError("All alphabet values must be unique")
        self.key = key
        self.ciph = AES.new(self._revb(self.key), AES.MODE_ECB)
        self.minlen = math.ceil(math.log(1000000) / math.log(radix))
        self.maxlen = 2 * math.floor(math.log(2 ** 96, radix))

    def _num_radix(self, X):
        """The _number that the _numeral string X represents in base radix
        when the numerals are valued in decreasing order of significance

        :Parameters:
          X : _numeral String
        :Return:
          x : Integer
        """
        x = 0
        for i in range(0, len(X)):
            x = x * self.radix + int(X[i])
        return x

    def _num(self, X):
        """The integer that a byte array X represents when the bytes are
        valued in decreasing order of significance (i.e. big-endian)

        :Parameters:
          X : Byte Array, X, represented in bytes
        :Return:
          x : Integer
        """
        return int.from_bytes(X, "big")

    def _str_m_radix(self, m, x):
        """Given a nonnegative integer less than radix^m, the representation
        of x as a string of m numerals in base radix, in decreasing order
        of significance
        :Parameters:
          m : Length of numerals for the numeral string
          x : Integer such that 0 <= x < radix^m
        :Return:
          X : numeral String with length of m
        """
        X = []
        for i in range(0, m):
            X.insert(0, str(x % self.radix))
            x = x // self.radix
        return X

    def _rev(self, X):
        """Given a numeral string X, the numeral string that consists of the
        numerals of X in reverse order
        :Parameters:
         X : numeral String
        :Return:
         Y : numeral String
        """
        return X[::-1]

    def _revb(self, X):
        """Given a bytearray X the byte array that consists of the bytes of X
        in reverse order
        :parameters:
         X : Bytearray
        :Return:
         Y : Bytearray
        """
        return X[::-1]

    def _check_numeral_string(self, X):
        # This function assumes X is a string or list of numeral integers
        # First, check the length of X and throw error if not within range
        if not (self.minlen <= len(X) <= self.maxlen):
            raise ValueError('Length must be between {} and {}'
                             .format(self.minlen, self.maxlen))
        # Make sure all elements of X are a valid int within the radix
        for i in X:
            try:
                num = int(i)
                if not (0 <= num < self.radix):
                    raise ValueError('Element must be integer within base {}'
                                     .format(self.radix))
            except ValueError:
                raise ValueError('Element must be an integer within base {}'
                                 .format(self.radix))

    def _convert_tweak(self, T_56):
        """ Takes a 56 bit tweak value and converts it to a 64 bit tweak value
        suitable for FF3 Encrypt.
        Tweak is converted per Step 3 in Algorithm 9: FF3-1.Encrypt(K, T, X)
        : Parameters:
         T_56: A 56-bit tweak value matching FF3-1 specification
        : Return:
         T_64: A 64-bit tweak value converted per Step 3
        """
        if type(T_56) is not (bytes or bytearray):
            raise TypeError('Tweak must be bytes or bytearray')
        if len(T_56) != 7:
            raise ValueError('Tweak must be 7 bytes or 56 bits in length')
        # Note: In Python all bitwise operations must be done on integers
        # Let TL = T[0..27] || 0^4
        # Split t_l, shift_r to get rid of last 4 bits, shift_l back to pad 0
        t_l = int.from_bytes(T_56[0:4], 'big')
        t_l = (t_l >> 4) << 4
        t_l = t_l.to_bytes(4, 'big')
        # Let TR = T[32..55] || T[28..31] || 0^4
        # Grab last three bytes, shift one byte left, append 28...31 and shift
        t_r = int.from_bytes(T_56[4:], 'big')
        t_r = t_r << 8
        t_r = t_r | ((T_56[3] & 15) << 4)
        t_r = t_r.to_bytes(4, 'big')
        return t_l + t_r

    def _plaintext_to_numeral_string(self, pt):
        """Takes a plaintext under a given alphabet and converts to a numeral
        string. Also validates the plaintext does not contain invalid
        characters
        :Parameters:
         pt : plaintext - all chars must be within self.alphabet
        : Return:
         X : numeral string of integers
        """
        X = []
        for char in pt:
            try:
                X.append(self.alphabet.index(char))
            except ValueError:
                raise AlphabetValueError("Plaintext element {} not in \
                    alphabet".format(char))
        return X

    def _numeral_string_to_plaintext(self, numeral_string):
        """Takes a plaintext under a given alphabet and converts to a numeral
        string. Also validates the plaintext does not contain invalid
        characters
        :Parameters:
         numeral_string : A numeral string with values within alphabet
        : Return:
         pt : the numeral string converted to the appropriate index
        """
        pt = []
        for number in numeral_string:
            pt.append(self.alphabet[int(number)])
        pt = ''.join(pt)
        return pt

    def _encrypt_numeral_string(self, X, T):
        """Implements the FF3.Encrypt algorithm per NIST SP 800-38G rev. 1
        :Parameters:
         X : numeral String in base radix of length n, such that n is between
             minlen and maxlen
         T : Tweak bit string, T, bytearray such that len = 8
        :Return:
         Y : _numeral string Y such that LEN(Y) = n
        """
        n = len(X)
        # Step 1: Split _numeral string X into two substrings, A and B
        u = math.ceil(n / 2)
        v = n - u
        # Step 2:
        A, B = X[:u], X[u:n]
        # Step 3: Partition T into 32-bit T_L and T_R
        T_L, T_R = T[:4], T[4:]
        # Step 4: Iteration of the eight Feistel rounds...
        for i in range(0, 8):
            # Step 4.i: The partiy of the round _number determines the length m
            # of the substring A, and whether T_L or T_R is used as w in 4ii
            if (i % 2 == 0):
                m, w = u, T_R
            else:
                m, w = v, T_L
            # Step 4.ii: 32-bit encoding of i, XOR with W, concatenated with
            # with 96-bit encoding of B to produce a block, P
            w = bytearray(w)
            w[3] = w[3] ^ i
            P = w + self._num_radix(self._revb(B)).to_bytes(12,
                                                            byteorder='big')
            # Step 4.iii: The block cipher under the key is applied to P using
            # the byte-reversed ordering convention to produce a block, S
            S = self._revb(self.ciph.encrypt(self._revb(P)))
            # Step 4.iv: Convert S to a number y
            y = self._num(S)
            # Step 4.v: y is added to the number represented by substring A
            # Result is reduced modulo the mth power of radix
            c = (self._num_radix(self._rev(A)) + y) % (pow(self.radix, m))
            # Step 4.vi: Convert c to a _numeral string
            C = self._rev(self._str_m_radix(m, c))
            # Step 4.vii: Swap A and B for the next round
            # Rename substring B and substring A
            A = B
            # Step 4.viii: The modified A (i.e. C) is renamed as B
            B = C
        return A + B

    def _decrypt_numeral_string(self, X, T):
        """Implements the FF3.Decrypt algorithm per NIST SP 800-38G _rev. 1
        :parameters:
         X : _numeral String in base radix of length n, such that n is between
             minlen and maxlen
         T : Tweak bit string, T, bytearray such that len = 8
        :Return:
         Y : _numeral string Y such that LEN(Y) = n
        """
        n = len(X)
        # Step 1: Split _numeral string X into two substrings, A and B
        u = math.ceil(n / 2)
        v = n - u
        # Step 2:
        A, B = X[:u], X[u:n]
        # Step 3: Partition T into 32-bit T_L and T_R
        T_L, T_R = T[:4], T[4:]
        # Step 4: Iteration of the eigh Feistel rounds...
        for i in range(7, -1, -1):
            # Step 4.i: The partiy of the round _number determines the length
            # of the substring A, and whether T_L or T_R is used as w in 4ii
            if (i % 2 == 0):
                m, w = u, T_R
            else:
                m, w = v, T_L
            # Step 4.ii: 32-bit encoding of i, XOR with W, concatenated with
            # with 96-bit encoding of A to produce a block, P
            w = bytearray(w)
            w[3] = w[3] ^ i
            P = w + self._num_radix(self._revb(A)).to_bytes(12,
                                                            byteorder='big')
            # Step 4.iii: The block cipher under the key is applied to P using
            # the byte-reversed ordering convention to produce a block, S
            S = self._revb(self.ciph.encrypt(self._revb(P)))
            # Step 4.iv: Convert S to a number y
            y = self._num(S)
            # Step 4.v: y is subtracted from the number represented by B
            # Result is reduced modulo the mth power of radix
            c = (self._num_radix(self._rev(B)) - y) % (pow(self.radix, m))
            # Step 4.vi: Convert c to a numeral string
            C = self._rev(self._str_m_radix(m, c))
            # Step 4.vii: Swap A and B for the next round
            # Rename substring A to substring B
            B = A
            # Step 4.viii: The modified B (i.e. C) is renamed as A
            A = C
        return A + B

    def encrypt(self, pt, T_56):
        """Implements the FF3-1.Encrypt algorithm per NIST SP 800-38G rev. 1
        :Parameters:
         pt : plaintext, must be characters within alphabet and within
         minlen and maxlen
         T_56 : Tweak bit string, T, bytearray such that len = 7
        :Return:
         ct : the pt encrypted via the key and tweak, converted to string
        """
        if not (self.minlen <= len(pt) <= self.maxlen):
            raise ValueError("Length of pt must be between \
                {} and {}".format(self.minlen, self.maxlen))
        X = self._plaintext_to_numeral_string(pt)
        T_64 = self._convert_tweak(T_56)
        Y = self._encrypt_numeral_string(X, T_64)
        return self._numeral_string_to_plaintext(Y)

    def decrypt(self, ct, T_56):
        """Implements the FF3-1.Decrypt algorithm per NIST SP 800-38G rev. 1
        :Parameters:
         ct : ciphertext, must be characters within alphabet and within
         minlen and maxlen
         T_56 : Tweak bit string, T, bytearray such that len = 7
        :Return:
         pt : the ct decrypted via the key and tweak, converted to string
        """
        if not (self.minlen <= len(ct) <= self.maxlen):
            raise ValueError("Length of ct must be between \
                {} and {}".format(self.minlen, self.maxlen))
        X = self._plaintext_to_numeral_string(ct)
        T_64 = self._convert_tweak(T_56)
        Y = self._decrypt_numeral_string(X, T_64)
        return self._numeral_string_to_plaintext(Y)


class RadixOutOfRangeError(ValueError):
    pass


class AlphabetOutOfRangeError(ValueError):
    pass


class AlphabetValueError(ValueError):
    pass
