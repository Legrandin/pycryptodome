# -*- coding: utf-8 -*-
#
#  PublicKey/RSA.py : RSA public key primitive
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

"""RSA public-key cryptography algorithm (signature and encryption).

RSA_ is the most widespread and used public key algorithm. Its security is
based on the difficulty of factoring large integers. The algorithm has
withstood attacks for 30 years, and it is therefore considered reasonably
secure for new designs.

The algorithm can be used for both confidentiality (encryption) and
authentication (digital signature). It is worth noting that signing and
decryption are significantly slower than verification and encryption.
The cryptograhic strength is primarily linked to the length of the modulus *n*.
In 2012, a sufficient length is deemed to be 2048 bits. For more information,
see the most recent ECRYPT_ report.

Both RSA ciphertext and RSA signature are as big as the modulus *n* (256
bytes if *n* is 2048 bit long).

This module provides facilities for generating fresh, new RSA keys, constructing
them from known components, exporting them, and importing them.

    >>> from Crypto.PublicKey import RSA
    >>>
    >>> key = RSA.generate(2048)
    >>> f = open('mykey.pem','w')
    >>> f.write(key.exportKey('PEM'))
    >>> f.close()
    ...
    >>> f = open('mykey.pem','r')
    >>> key = RSA.importKey(f.read())

Even though you may choose to  directly use the methods of an RSA key object
to perform the primitive cryptographic operations (e.g. `RsaKey._encrypt`),
it is recommended to use one of the standardized schemes instead (like
`Crypto.Cipher.PKCS1_v1_5` or `Crypto.Signature.PKCS1_v1_5`).

.. _RSA: http://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. _ECRYPT: http://www.ecrypt.eu.org/documents/D.SPA.17.pdf

:sort: generate,construct,importKey
"""

__all__ = ['generate', 'construct', 'importKey', 'RSAImplementation',
    'RsaKey', 'oid' , 'algorithmIdentifier' ]

from Crypto.Util.py3compat import *

import binascii
import struct

from Crypto import Random
from Crypto.IO import PKCS8, PEM

from Crypto.Util.asn1 import (
                DerNull,
                DerSequence,
                DerBitString,
                DerObjectId,
                newDerSequence,
                newDerBitString
                )

from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import (test_probable_prime,
                                generate_probable_prime, COMPOSITE)


class RsaKey(object):
    """Class defining an actual RSA key.

    :undocumented: __getstate__, __setstate__, __repr__, __getattr__
    """
    #: Dictionary of RSA parameters.
    #:
    #: A public key will only have the following entries:
    #:
    #:  - **n**, the modulus.
    #:  - **e**, the public exponent.
    #:
    #: A private key will also have:
    #:
    #:  - **d**, the private exponent.
    #:  - **p**, the first factor of n.
    #:  - **q**, the second factor of n.
    #:  - **u**, the CRT coefficient (1/p) mod q.
    _keydata = ['n', 'e', 'd', 'p', 'q', 'u']

    def __init__(self, key_dict):
        input_set = set(key_dict.keys())
        public_set = set(('n' , 'e'))
        private_set = public_set | set(('p' , 'q', 'd', 'u'))
        if input_set not in (private_set, public_set):
            raise ValueError("Some RSA components are missing")
        self._key = dict(key_dict)

    def __getattr__(self, attrname):
        try:
            return int(self._key[attrname])
        except KeyError:
            raise AttributeError(attrname)

    def _encrypt(self, plaintext):
        if not 0 < plaintext < self.n:
            raise ValueError("Plaintext too large")
        e, n = self._key['e'], self._key['n']
        return int(pow(Integer(plaintext), e, n))

    def _decrypt(self, ciphertext):
        if not 0 < ciphertext < self.n:
            raise ValueError("Ciphertext too large")
        if not self.has_private():
            raise TypeError("This is not a private key")

        e, d, n, p, q, u = [self._key[comp] for comp in ('e', 'd', 'n', 'p', 'q', 'u')]

        # Blinded RSA decryption (to prevent timing attacks):
        # Step 1: Generate random secret blinding factor r, such that 0 < r < n-1
        r = Integer.random_range(min_inclusive=1, max_exclusive=n)
        # Step 2: Compute c' = c * r**e mod n
        cp = Integer(ciphertext) * pow(r, e, n) % n
        # Step 3: Compute m' = c'**d mod n       (ordinary RSA decryption)
        m1 = pow(cp, d % (p - 1), p)
        m2 = pow(cp, d % (q - 1), q)
        h = m2 - m1
        while h < 0:
            h += q
        h = (h * u) % q
        mp = h * p + m1
        # Step 4: Compute m = m**(r-1) mod n
        result = (r.inverse(n) * mp) % n
        # Verify no faults occured
        if ciphertext != pow(result, e, n):
            raise ValueError("Fault detected in RSA decryption")
        return result

    def has_private(self):
        return 'd' in self._key

    def publickey(self):
        return RsaKey(dict([(k, self._key[k]) for k in ('n', 'e')]))

    def __eq__(self, other):
        return self._key == other._key

    def __ne__(self, other):
        return self._key != other._key

    def __getstate__(self):
        # RSA key is not pickable
        from pickle import PicklingError
        raise PicklingError

    def __repr__(self):
        attrs = []
        for k in self._keydata:
            if k == 'n':
                attrs.append("n(%d)" % (self.size()+1,))
            elif hasattr(self.key, k):
                attrs.append(k)
        if self.has_private():
            attrs.append("private")
        # PY3K: This is meant to be text, do not change to bytes (data)
        return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))

    def exportKey(self, format='PEM', passphrase=None, pkcs=1, protection=None, randfunc=None):
        """Export this RSA key.

        :Parameters:
          format : string
            The format to use for wrapping the key:

            - *'DER'*. Binary encoding.
            - *'PEM'*. Textual encoding, done according to `RFC1421`_/`RFC1423`_.
            - *'OpenSSH'*. Textual encoding, done according to OpenSSH specification.
              Only suitable for public keys (not private keys).

          passphrase : string
            For private keys only. The pass phrase used for deriving the encryption
            key.

          pkcs : integer
            For *DER* and *PEM* format only.
            The PKCS standard to follow for assembling the components of the key.
            You have two choices:

            - **1** (default): the public key is embedded into
              an X.509 ``SubjectPublicKeyInfo`` DER SEQUENCE.
              The private key is embedded into a `PKCS#1`_
              ``RSAPrivateKey`` DER SEQUENCE.
            - **8**: the private key is embedded into a `PKCS#8`_
              ``PrivateKeyInfo`` DER SEQUENCE. This value cannot be used
              for public keys.

          protection : string
            The encryption scheme to use for protecting the private key.

            If ``None`` (default), the behavior depends on ``format``:

            - For *DER*, the *PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC*
              scheme is used. The following operations are performed:

                1. A 16 byte Triple DES key is derived from the passphrase
                   using `Crypto.Protocol.KDF.PBKDF2` with 8 bytes salt,
                   and 1 000 iterations of `Crypto.Hash.HMAC`.
                2. The private key is encrypted using CBC.
                3. The encrypted key is encoded according to PKCS#8.

            - For *PEM*, the obsolete PEM encryption scheme is used.
              It is based on MD5 for key derivation, and Triple DES for encryption.

            Specifying a value for ``protection`` is only meaningful for PKCS#8
            (that is, ``pkcs=8``) and only if a pass phrase is present too.

            The supported schemes for PKCS#8 are listed in the
            `Crypto.IO.PKCS8` module (see ``wrap_algo`` parameter).

          randfunc : callable
            A function that provides random bytes. Only used for PEM encoding.
            The default is `Crypto.Random.get_random_bytes`.

        :Return: A byte string with the encoded public or private half
          of the key.
        :Raise ValueError:
            When the format is unknown or when you try to encrypt a private
            key with *DER* format and PKCS#1.
        :attention:
            If you don't provide a pass phrase, the private key will be
            exported in the clear!

        .. _RFC1421:    http://www.ietf.org/rfc/rfc1421.txt
        .. _RFC1423:    http://www.ietf.org/rfc/rfc1423.txt
        .. _`PKCS#1`:   http://www.ietf.org/rfc/rfc3447.txt
        .. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
        """

        if passphrase is not None:
            passphrase = tobytes(passphrase)

        if randfunc is None:
            randfunc = Random.get_random_bytes

        if format=='OpenSSH':
               eb, nb = [self._key[comp].to_bytes() for comp in ('e', 'n')]
               if bord(eb[0]) & 0x80: eb=bchr(0x00)+eb
               if bord(nb[0]) & 0x80: nb=bchr(0x00)+nb
               keyparts = [ b('ssh-rsa'), eb, nb ]
               keystring = b('').join([ struct.pack(">I",len(kp))+kp for kp in keyparts])
               return b('ssh-rsa ')+binascii.b2a_base64(keystring)[:-1]

        # DER format is always used, even in case of PEM, which simply
        # encodes it into BASE64.
        if self.has_private():
                binary_key = newDerSequence(
                        0,
                        self.n,
                        self.e,
                        self.d,
                        self.p,
                        self.q,
                        self.d % (self.p-1),
                        self.d % (self.q-1),
                        Integer(self.q).inverse(self.p)
                    ).encode()
                if pkcs==1:
                    keyType = 'RSA PRIVATE'
                    if format=='DER' and passphrase:
                        raise ValueError("PKCS#1 private key cannot be encrypted")
                else: # PKCS#8
                    if format=='PEM' and protection is None:
                        keyType = 'PRIVATE'
                        binary_key = PKCS8.wrap(binary_key, oid, None)
                    else:
                        keyType = 'ENCRYPTED PRIVATE'
                        if not protection:
                            protection = 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'
                        binary_key = PKCS8.wrap(binary_key, oid, passphrase, protection)
                        passphrase = None
        else:
                keyType = "RSA PUBLIC"
                binary_key = newDerSequence(
                    algorithmIdentifier,
                    newDerBitString(
                        newDerSequence( self.n, self.e )
                        )
                    ).encode()
        if format=='DER':
            return binary_key
        if format=='PEM':
            pem_str = PEM.encode(binary_key, keyType+" KEY", passphrase, randfunc)
            return tobytes(pem_str)
        raise ValueError("Unknown key format '%s'. Cannot export the RSA key." % format)


def generate(bits, randfunc=None, e=65537):
    """Create a new RSA key.

    The algorithm closely follows NIST `FIPS 186-4`_ in its
    sections B.3.1 and B.3.3. The modulus is the product of
    two non-strong probable primes.
    Each prime passes a suitable number of Miller-Rabin tests
    with random bases and a single Lucas test.

    :Parameters:
      bits : integer
        Key length, or size (in bits) of the RSA modulus.
        It must be at least 1024.
        The FIPS standard only defines 1024, 2048 and 3072.
      randfunc : callable
        Function that returns random bytes.
        The default is `Crypto.Random.get_random_bytes`.
      e : integer
        Public RSA exponent. It must be an odd positive integer.
        It is typically a small number with very few ones in its
        binary representation.
        The FIPS standard requires the public exponent to be
        at least 65537 (the default).

    :Return: An RSA key object (`RsaKey`).

    .. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if bits < 1024:
        raise ValueError("RSA modulus length must be >= 1024")
    if e % 2 == 0 or e < 3:
        raise ValueError("RSA public exponent must be a positive, odd integer larger than 2.")

    if randfunc is None:
        randfunc = Random.get_random_bytes

    d = n = Integer(1)
    e = Integer(e)

    while n.size_in_bits() != bits and d < (1 << (bits // 2)):
        # Generate the prime factors of n: p and q.
        # By construciton, their product is always
        # 2^{bits-1} < p*q < 2^bits.
        size_q = bits // 2
        size_p = bits - size_q

        min_p = min_q = (Integer(1) << (2 * size_q - 1)).sqrt()
        if size_q != size_p:
            min_p = (Integer(1) << (2 * size_p - 1)).sqrt()

        def filter_p(candidate):
            return candidate > min_p and (candidate - 1).gcd(e) == 1

        p = generate_probable_prime(exact_bits=size_p,
                                    randfunc=randfunc,
                                    prime_filter=filter_p)

        min_distance = Integer(1) << (bits // 2 - 100)

        def filter_q(candidate):
            return candidate > min_q and (candidate - 1).gcd(e) == 1 \
                                     and abs(candidate - p) > min_distance

        q = generate_probable_prime(exact_bits=size_q,
                                    randfunc=randfunc,
                                    prime_filter=filter_q)

        n = p * q
        lcm = (p - 1).lcm(q - 1)
        d = e.inverse(lcm)

    if p > q:
        p, q = q, p

    u = p.inverse(q)

    key_dict = dict(list(zip(('n', 'e', 'd', 'p', 'q', 'u'),
                        (n, e, d, p, q, u))))
    return RsaKey(key_dict)


def construct(tup, consistency_check=True):
    """Construct an RSA key from a tuple of valid RSA components.

    The modulus **n** must be the product of two primes.
    The public exponent **e** must be odd and larger than 1.

    In case of a private key, the following equations must apply:

    - e != 1
    - p*q = n
    - e*d = 1 mod lcm[(p-1)(q-1)]
    - p*u = 1 mod q

    :Parameters:
     tup : tuple
        A tuple of long integers, with at least 2 and no
        more than 6 items. The items come in the following order:

            1. RSA modulus (*n*).
            2. Public exponent (*e*).
            3. Private exponent (*d*).
               Only required if the key is private.
            4. First factor of *n* (*p*).
               Optional, but factor q must also be present.
            5. Second factor of *n* (*q*). Optional.
            6. CRT coefficient, *(1/p) mod q* (*u*). Optional.
     consistency_check : boolean
        If *True*, the library will verify that the provided components
        fulfil the main RSA properties.

    :Raise ValueError:
        When the key being imported fails the most basic RSA validity checks.
    :Return: An RSA key object (`RsaKey`).
    """

    comp_names = 'n', 'e', 'd', 'p', 'q', 'u'
    key_dict = dict(list(zip(comp_names, list(map(Integer, tup)))))
    n, e, d, p, q, u = [key_dict.get(comp) for comp in comp_names]

    if d is not None:

        if None in (p, q):
            # Compute factors p and q from the private exponent d.
            # We assume that n has no more than two factors.
            # See 8.2.2(i) in Handbook of Applied Cryptography.
            ktot = d * e - 1
            # The quantity d*e-1 is a multiple of phi(n), even,
            # and can be represented as t*2^s.
            t = ktot
            while t % 2 ==0:
                t //= 2
            # Cycle through all multiplicative inverses in Zn.
            # The algorithm is non-deterministic, but there is a 50% chance
            # any candidate a leads to successful factoring.
            # See "Digitalized Signatures and Public Key Functions as Intractable
            # as Factorization", M. Rabin, 1979
            spotted = False
            a = Integer(2)
            while not spotted and a < 100:
                k = Integer(t)
                # Cycle through all values a^{t*2^i}=a^k
                while k < ktot:
                    cand = pow(a, k, n)
                    # Check if a^k is a non-trivial root of unity (mod n)
                    if cand != 1 and cand != (n - 1) and pow(cand, 2, n) == 1:
                        # We have found a number such that (cand-1)(cand+1)=0 (mod n).
                        # Either of the terms divides n.
                        p = Integer(n).gcd(cand + 1)
                        spotted = True
                        break
                    k *= 2
                # This value was not any good... let's try another!
                a += 2
            if not spotted:
                raise ValueError("Unable to compute factors p and q from exponent d.")
            # Found !
            assert ((n % p) == 0)
            q = n // p

        if u is None:
            u = p.inverse(q)

        key_dict['p'] = p
        key_dict['q'] = q
        key_dict['u'] = u

    # Build key object
    key = RsaKey(key_dict)

    # Very consistency of the key
    fmt_error = False
    if consistency_check:
        # Modulus and public exponent must be coprime
        fmt_error = e <= 1 or e >= n
        fmt_error |= Integer(n).gcd(e) != 1

        # For RSA, modulus must be odd
        fmt_error |= not n & 1

        if not fmt_error and key.has_private():
            # Modulus and private exponent must be coprime
            fmt_error = d <= 1 or d >= n
            fmt_error |= Integer(n).gcd(d) != 1
            # Modulus must be product of 2 primes
            fmt_error |= (p * q != n)
            fmt_error |= test_probable_prime(p) == COMPOSITE
            fmt_error |= test_probable_prime(q) == COMPOSITE
            # See Carmichael theorem
            phi = (p - 1) * (q - 1)
            lcm = phi // (p - 1).gcd(q - 1)
            fmt_error |= (e * d % int(lcm)) != 1
            if hasattr(key, 'u'):
                # CRT coefficient
                fmt_error |= u <= 1 or u >= q
                fmt_error |= (p * u % q) != 1
            else:
                fmt_error = True

    if fmt_error:
        raise ValueError("Invalid RSA key components")

    return key


def _importKeyDER(extern_key, passphrase):
    """Import an RSA key (public or private half), encoded in DER form."""

    try:

        der = DerSequence().decode(extern_key)

        # Try PKCS#1 first, for a private key
        if len(der) == 9 and der.hasOnlyInts() and der[0] == 0:
            # ASN.1 RSAPrivateKey element
            del der[6:]     # Remove d mod (p-1),
                            # d mod (q-1), and
                            # q^{-1} mod p
            der.append(Integer(der[4]).inverse(der[5]))  # Add p^{-1} mod q
            del der[0]      # Remove version
            return construct(der[:])

        # Keep on trying PKCS#1, but now for a public key
        if len(der) == 2:
            try:
                # The DER object is an RSAPublicKey SEQUENCE with
                # two elements
                if der.hasOnlyInts():
                    return construct(der[:])
                # The DER object is a SubjectPublicKeyInfo SEQUENCE
                # with two elements: an 'algorithmIdentifier' and a
                # 'subjectPublicKey'BIT STRING.
                # 'algorithmIdentifier' takes the value given at the
                # module level.
                # 'subjectPublicKey' encapsulates the actual ASN.1
                # RSAPublicKey element.
                if der[0] == algorithmIdentifier:
                    bitmap = DerBitString().decode(der[1])
                    rsaPub = DerSequence().decode(bitmap.value)
                    if len(rsaPub) == 2 and rsaPub.hasOnlyInts():
                        return construct(rsaPub[:])
            except (ValueError, EOFError):
                pass

        # Try to see if this is an X.509 DER certificate
        # (Certificate ASN.1 type)
        if len(der) == 3:
            from Crypto.PublicKey import _extract_sp_info
            try:
                sp_info = _extract_sp_info(der)
                return _importKeyDER(sp_info, passphrase)
            except ValueError:
                pass

        # Try PKCS#8 (possibly encrypted)
        k = PKCS8.unwrap(extern_key, passphrase)
        if k[0] == oid:
            return _importKeyDER(k[1], passphrase)

    except (ValueError, EOFError):
        pass

    raise ValueError("RSA key format is not supported")

def importKey(extern_key, passphrase=None):
    """Import an RSA key (public or private half), encoded in standard
    form.

    :Parameter extern_key:
        The RSA key to import, encoded as a byte string.

        An RSA public key can be in any of the following formats:

        - X.509 certificate (binary or PEM format)
        - X.509 ``subjectPublicKeyInfo`` DER SEQUENCE (binary or PEM
          encoding)
        - `PKCS#1`_ ``RSAPublicKey`` DER SEQUENCE (binary or PEM encoding)
        - OpenSSH (textual public key only)

        An RSA private key can be in any of the following formats:

        - PKCS#1 ``RSAPrivateKey`` DER SEQUENCE (binary or PEM encoding)
        - `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
          DER SEQUENCE (binary or PEM encoding)
        - OpenSSH (textual public key only)

        For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

        The private key may be encrypted by means of a certain pass phrase
        either at the PEM level or at the PKCS#8 level.
    :Type extern_key: string

    :Parameter passphrase:
        In case of an encrypted private key, this is the pass phrase from
        which the decryption key is derived.
    :Type passphrase: string

    :Return: An RSA key object (`RsaKey`).

    :Raise ValueError/IndexError/TypeError:
        When the given key cannot be parsed (possibly because the pass
        phrase is wrong).

    .. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
    .. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
    .. _`PKCS#1`: http://www.ietf.org/rfc/rfc3447.txt
    .. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt
    """
    extern_key = tobytes(extern_key)
    if passphrase is not None:
        passphrase = tobytes(passphrase)

    if extern_key.startswith(b('-----')):
        # This is probably a PEM encoded key.
        (der, marker, enc_flag) = PEM.decode(tostr(extern_key), passphrase)
        if enc_flag:
            passphrase = None
        return _importKeyDER(der, passphrase)

    if extern_key.startswith(b('ssh-rsa ')):
            # This is probably an OpenSSH key
            keystring = binascii.a2b_base64(extern_key.split(b(' '))[1])
            keyparts = []
            while len(keystring) > 4:
                l = struct.unpack(">I", keystring[:4])[0]
                keyparts.append(keystring[4:4 + l])
                keystring = keystring[4 + l:]
            e = Integer.from_bytes(keyparts[1])
            n = Integer.from_bytes(keyparts[2])
            return construct([n, e])

    if bord(extern_key[0]) == 0x30:
            # This is probably a DER encoded key
            return _importKeyDER(extern_key, passphrase)

    raise ValueError("RSA key format is not supported")

#: `Object ID`_ for the RSA encryption algorithm. This OID often indicates
#: a generic RSA key, even when such key will be actually used for digital
#: signatures.
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
oid = "1.2.840.113549.1.1.1"

#: This is the standard DER object that qualifies a cryptographic algorithm
#: in ASN.1-based data structures (e.g. X.509 certificates).
algorithmIdentifier = DerSequence(
  [DerObjectId(oid).encode(),      # algorithm field
  DerNull().encode()]              # parameters field
  ).encode()
