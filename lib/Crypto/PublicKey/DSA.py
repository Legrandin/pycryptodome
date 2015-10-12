# -*- coding: utf-8 -*-
#
#  PublicKey/DSA.py : DSA signature primitive
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

"""DSA public-key signature algorithm.

DSA_ is a widespread public-key signature algorithm. Its security is
based on the discrete logarithm problem (DLP_). Given a cyclic
group, a generator *g*, and an element *h*, it is hard
to find an integer *x* such that *g^x = h*. The problem is believed
to be difficult, and it has been proved such (and therefore secure) for
more than 30 years.

The group is actually a sub-group over the integers modulo *p*, with *p* prime.
The sub-group order is *q*, which is prime too; it always holds that *(p-1)* is a multiple of *q*.
The cryptographic strength is linked to the magnitude of *p* and *q*.
The signer holds a value *x* (*0<x<q-1*) as private key, and its public
key (*y* where *y=g^x mod p*) is distributed.

In 2012, a sufficient size is deemed to be 2048 bits for *p* and 256 bits for *q*.
For more information, see the most recent ECRYPT_ report.

DSA is reasonably secure for new designs.

The algorithm can only be used for authentication (digital signature).
DSA cannot be used for confidentiality (encryption).

The values *(p,q,g)* are called *domain parameters*;
they are not sensitive but must be shared by both parties (the signer and the verifier).
Different signers can share the same domain parameters with no security
concerns.

The DSA signature is twice as big as the size of *q* (64 bytes if *q* is 256 bit
long).

This module provides facilities for generating new DSA keys and for constructing
them from known components. DSA keys allows you to perform basic signing and
verification.

    >>> from Crypto.PublicKey import DSA
    >>> from Crypto.Signature.DSS
    >>> from Crypto.Hash import SHA256
    >>>
    >>> message = b"Hello"
    >>> key = DSA.generate(2048)
    >>> f = open("public_key.pem", "w")
    >>> f.write(key.publickey().exportKey(key))
    >>> hash_obj = SHA256.new(message)
    >>> signer = DSS.new(key, 'fips-186-3')
    >>> signature = key.sign(hash_obj)
    >>> ...
    >>> f = open("public_key.pem", "r")
    >>> hash_obj = SHA256.new(message)
    >>> pub_key = DSA.importKey(f.read())
    >>> if pub_key.verify(hash_obj, signature):
    >>>     print "OK"
    >>> else:
    >>>     print "Incorrect signature"

.. _DSA: http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _DLP: http://www.cosic.esat.kuleuven.be/publications/talk-78.pdf
.. _ECRYPT: http://www.ecrypt.eu.org/documents/D.SPA.17.pdf
"""

__all__ = ['generate', 'construct', 'DSAImplementation',
           'DsaKey', 'importKey' ]

import binascii
import struct
import itertools

from Crypto.Util.py3compat import *

from Crypto import Random
from Crypto.IO import PKCS8, PEM
from Crypto.Hash import SHA256
from Crypto.Util.asn1 import (
                DerObject, DerSequence,
                DerInteger, DerObjectId,
                DerBitString, newDerSequence,
                newDerBitString
                )

from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import (test_probable_prime, COMPOSITE,
                                   PROBABLY_PRIME)


#   ; The following ASN.1 types are relevant for DSA
#
#   SubjectPublicKeyInfo    ::=     SEQUENCE {
#       algorithm   AlgorithmIdentifier,
#       subjectPublicKey BIT STRING
#   }
#
#   id-dsa ID ::= { iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
#
#   ; See RFC3279
#   Dss-Parms  ::=  SEQUENCE  {
#       p INTEGER,
#       q INTEGER,
#       g INTEGER
#   }
#
#   DSAPublicKey ::= INTEGER
#
#   DSSPrivatKey_OpenSSL ::= SEQUENCE
#       version INTEGER,
#       p INTEGER,
#       q INTEGER,
#       g INTEGER,
#       y INTEGER,
#       x INTEGER
#   }
#

class DsaKey(object):
    """Class defining an actual DSA key.

    :undocumented: __getstate__, __setstate__, __repr__, __getattr__
    """
    #: Dictionary of DSA parameters.
    #:
    #: A public key will only have the following entries:
    #:
    #:  - **y**, the public key.
    #:  - **g**, the generator.
    #:  - **p**, the modulus.
    #:  - **q**, the order of the sub-group.
    #:
    #: A private key will also have:
    #:
    #:  - **x**, the private key.
    _keydata = ['y', 'g', 'p', 'q', 'x']

    def __init__(self, key_dict):
        input_set = set(key_dict.keys())
        public_set = set(('y' , 'g', 'p', 'q'))
        if not public_set.issubset(input_set):
            raise ValueError("Some DSA components are missing = %s" %
                             str(public_set - input_set))
        extra_set = input_set - public_set
        if extra_set and extra_set != set(('x',)):
            raise ValueError("Unknown DSA components = %s" %
                             str(extra_set - set(('x',))))
        self._key = dict(key_dict)

    def _sign(self, m, k):
        if not self.has_private():
            raise TypeError("DSA public key cannot be used for signing")
        if not (1 < k < self.q):
            raise ValueError("k is not between 2 and q-1")

        x, q, p, g = [self._key[comp] for comp in ['x', 'q', 'p', 'g']]

        blind_factor = Integer.random_range(min_inclusive=1,
                                           max_exclusive=q)
        inv_blind_k = (blind_factor * k).inverse(q)
        blind_x = x * blind_factor

        r = pow(g, k, p) % q  # r = (g**k mod p) mod q
        s = (inv_blind_k * (blind_factor * m + blind_x * r)) % q
        return map(int, (r, s))

    def _verify(self, m, sig):
        r, s = sig
        y, q, p, g = [self._key[comp] for comp in ['y', 'q', 'p', 'g']]
        if not (0 < r < q) or not (0 < s < q):
            return False
        w = Integer(s).inverse(q)
        u1 = (w * m) % q
        u2 = (w * r) % q
        v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
        return v == r

    def has_private(self):
        return 'x' in self._key

    def can_encrypt(self):
        return False

    def can_sign(self):
        return True

    def publickey(self):
        public_components = dict((k, self._key[k]) for k in ('y', 'g', 'p', 'q'))
        return DsaKey(public_components)

    def __eq__(self, other):
        if bool(self.has_private()) != bool(other.has_private()):
            return False

        result = True
        for comp in self._keydata:
            result = result and (getattr(self._key, comp, None) ==
                                 getattr(other._key, comp, None))
        return result

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getstate__(self):
        # DSA key is not pickable
        from pickle import PicklingError
        raise PicklingError

    def domain(self):
        """The DSA domain parameters: *p*, *q* and *g*. """

        return map(int, [self._key[comp] for comp in 'p', 'q', 'g'])

    def __repr__(self):
        attrs = []
        for k in self._keydata:
            if k == 'p':
                attrs.append("p(%d)" % (self.size()+1,))
            elif hasattr(self, k):
                attrs.append(k)
        if self.has_private():
            attrs.append("private")
        # PY3K: This is meant to be text, do not change to bytes (data)
        return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))

    def __getattr__(self, item):
        try:
            return int(self._key[item])
        except KeyError:
            raise AttributeError(item)

    def exportKey(self, format='PEM', pkcs8=None, passphrase=None,
                  protection=None, randfunc=None):
        """Export this DSA key.

        :Parameters:
          format : string
            The format to use for wrapping the key:

            - *'DER'*. Binary encoding.
            - *'PEM'*. Textual encoding, done according to `RFC1421`_/
              `RFC1423`_ (default).
            - *'OpenSSH'*. Textual encoding, one line of text, see `RFC4253`_.
              Only suitable for public keys, not private keys.

          passphrase : string
            For private keys only. The pass phrase to use for deriving
            the encryption key.

          pkcs8 : boolean
            For private keys only. If ``True`` (default), the key is arranged
            according to `PKCS#8`_ and if `False`, according to the custom
            OpenSSL/OpenSSH encoding.

          protection : string
            The encryption scheme to use for protecting the private key.
            It is only meaningful when a pass phrase is present too.

            If ``pkcs8`` takes value ``True``, ``protection`` is the PKCS#8
            algorithm to use for deriving the secret and encrypting
            the private DSA key.
            For a complete list of algorithms, see `Crypto.IO.PKCS8`.
            The default is *PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC*.

            If ``pkcs8`` is ``False``, the obsolete PEM encryption scheme is
            used. It is based on MD5 for key derivation, and Triple DES for
            encryption. Parameter ``protection`` is ignored.

            The combination ``format='DER'`` and ``pkcs8=False`` is not allowed
            if a passphrase is present.

          randfunc : callable
            A function that returns random bytes.
            By default it is `Crypto.Random.get_random_bytes`.

        :Return: A byte string with the encoded public or private half
          of the key.
        :Raise ValueError:
            When the format is unknown or when you try to encrypt a private
            key with *DER* format and OpenSSL/OpenSSH.
        :attention:
            If you don't provide a pass phrase, the private key will be
            exported in the clear!

        .. _RFC1421:    http://www.ietf.org/rfc/rfc1421.txt
        .. _RFC1423:    http://www.ietf.org/rfc/rfc1423.txt
        .. _RFC4253:    http://www.ietf.org/rfc/rfc4253.txt
        .. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
        """

        if passphrase is not None:
            passphrase = tobytes(passphrase)

        if randfunc is None:
            randfunc = Random.get_random_bytes

        if format == 'OpenSSH':
            tup1 = [self._key[x].to_bytes() for x in 'p', 'q', 'g', 'y']

            def func(x):
                if (bord(x[0]) & 0x80):
                    return bchr(0) + x
                else:
                    return x

            tup2 = map(func, tup1)
            keyparts = [b('ssh-dss')] + tup2
            keystring = b('').join(
                            [struct.pack(">I", len(kp)) + kp for kp in keyparts]
                            )
            return b('ssh-dss ') + binascii.b2a_base64(keystring)[:-1]

        # DER format is always used, even in case of PEM, which simply
        # encodes it into BASE64.
        params = newDerSequence(self.p, self.q, self.g)
        if self.has_private():
            if pkcs8 is None:
                pkcs8 = True
            if pkcs8:
                if not protection:
                    protection = 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'
                private_key = DerInteger(self.x).encode()
                binary_key = PKCS8.wrap(
                                private_key, oid, passphrase,
                                protection, key_params=params,
                                randfunc=randfunc
                                )
                if passphrase:
                    key_type = 'ENCRYPTED PRIVATE'
                else:
                    key_type = 'PRIVATE'
                passphrase = None
            else:
                if format != 'PEM' and passphrase:
                    raise ValueError("DSA private key cannot be encrypted")
                ints = [0, self.p, self.q, self.g, self.y, self.x]
                binary_key = newDerSequence(*ints).encode()
                key_type = "DSA PRIVATE"
        else:
            if pkcs8:
                raise ValueError("PKCS#8 is only meaningful for private keys")
            binary_key = newDerSequence(
                            newDerSequence(DerObjectId(oid), params),
                            newDerBitString(DerInteger(self.y))
                            ).encode()
            key_type = "DSA PUBLIC"

        if format == 'DER':
            return binary_key
        if format == 'PEM':
            pem_str = PEM.encode(
                                binary_key, key_type + " KEY",
                                passphrase, randfunc
                            )
            return tobytes(pem_str)
        raise ValueError("Unknown key format '%s'. Cannot export the DSA key." % format)


def _generate_domain(L, randfunc):
    """Generate a new set of DSA domain parameters"""

    N = { 1024:160, 2048:224, 3072:256 }.get(L)
    if N is None:
        raise ValueError("Invalid modulus length (%d)" % L)

    outlen = SHA256.digest_size * 8
    n = (L + outlen - 1) // outlen - 1  # ceil(L/outlen) -1
    b_ = L - 1 - (n * outlen)

    # Generate q (A.1.1.2)
    q = Integer(4)
    upper_bit = 1 << (N - 1)
    while test_probable_prime(q, randfunc) != PROBABLY_PRIME:
        seed = randfunc(64)
        U = Integer.from_bytes(SHA256.new(seed).digest()) & (upper_bit - 1)
        q = U | upper_bit | 1

    assert(q.size_in_bits() == N)

    # Generate p (A.1.1.2)
    offset = 1
    upper_bit = 1 << (L - 1)
    while True:
        V = [ SHA256.new(seed + Integer(offset + j).to_bytes()).digest()
              for j in xrange(n + 1) ]
        V = [ Integer.from_bytes(v) for v in V ]
        W = sum([V[i] * (1 << (i * outlen)) for i in xrange(n)],
                (V[n] & (1 << b_ - 1)) * (1 << (n * outlen)))

        X = Integer(W + upper_bit) # 2^{L-1} < X < 2^{L}
        assert(X.size_in_bits() == L)

        c = X % (q * 2)
        p = X - (c - 1)  # 2q divides (p-1)
        if p.size_in_bits() == L and \
           test_probable_prime(p, randfunc) == PROBABLY_PRIME:
               break
        offset += n + 1

    # Generate g (A.2.3, index=1)
    e = (p - 1) // q
    for count in itertools.count(1):
        U = seed + b("ggen") + bchr(1) + Integer(count).to_bytes()
        W = Integer.from_bytes(SHA256.new(U).digest())
        g = pow(W, e, p)
        if g != 1:
            break

    return (p, q, g, seed)


def generate(bits, randfunc=None, domain=None):
    """Generate a new DSA key pair.

    The algorithm follows Appendix A.1/A.2 and B.1 of `FIPS 186-4`_,
    respectively for domain generation and key pair generation.

    :Parameters:
      bits : integer
        Key length, or size (in bits) of the DSA modulus *p*.
        It must be 1024, 2048 or 3072.

      randfunc : callable
        Random number generation function; it accepts a single integer N
        and return a string of random data N bytes long.
        If not specified, the default from ``Crypto.Random`` is used.

      domain : list
        The DSA domain parameters *p*, *q* and *g* as a list of 3
        integers. Size of *p* and *q* must comply to `FIPS 186-4`_.
        If not specified, the parameters are created anew.

    :Return: A DSA key object (`DsaKey`).

    :Raise ValueError:
        When **bits** is too little, too big, or not a multiple of 64.

    .. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    if randfunc is None:
        randfunc = Random.get_random_bytes

    if domain:
        p, q, g = map(Integer, domain)

        ## Perform consistency check on domain parameters
        # P and Q must be prime
        fmt_error = test_probable_prime(p) == COMPOSITE
        fmt_error = test_probable_prime(q) == COMPOSITE
        # Verify Lagrange's theorem for sub-group
        fmt_error |= ((p - 1) % q) != 0
        fmt_error |= g <= 1 or g >= p
        fmt_error |= pow(g, q, p) != 1
        if fmt_error:
            raise ValueError("Invalid DSA domain parameters")
    else:
        p, q, g, _ = _generate_domain(bits, randfunc)

    L = p.size_in_bits()
    N = q.size_in_bits()

    if L != bits:
        raise ValueError("Mismatch between size of modulus (%d)"
                         " and 'bits' parameter (%d)" % (L, bits))

    if (L, N) not in [(1024, 160), (2048, 224),
                      (2048, 256), (3072, 256)]:
        raise ValueError("Lengths of p and q (%d, %d) are not compatible"
                         "to FIPS 186-3" % (L, N))

    if not 1 < g < p:
        raise ValueError("Incorrent DSA generator")

    # B.1.1
    c = Integer.random(exact_bits=N + 64)
    x = c % (q - 1) + 1 # 1 <= x <= q-1
    y = pow(g, x, p)

    key_dict = { 'y':y, 'g':g, 'p':p, 'q':q, 'x':x }
    return DsaKey(key_dict)


def construct(tup, consistency_check=True):
    """Construct a DSA key from a tuple of valid DSA components.

    :Parameters:
     tup : tuple
        A tuple of long integers, with 4 or 5 items
        in the following order:

            1. Public key (*y*).
            2. Sub-group generator (*g*).
            3. Modulus, finite field order (*p*).
            4. Sub-group order (*q*).
            5. Private key (*x*). Optional.
     consistency_check : boolean
        If *True*, the library will verify that the provided components
        fulfil the main DSA properties.

    :Raise PublicKey.ValueError:
        When the key being imported fails the most basic DSA validity checks.
    :Return: A DSA key object (`DsaKey`).
    """

    key_dict = dict(zip(('y', 'g', 'p', 'q', 'x'), map(Integer, tup)))
    key = DsaKey(key_dict)

    fmt_error = False
    if consistency_check:
        # P and Q must be prime
        fmt_error = test_probable_prime(key.p) == COMPOSITE
        fmt_error = test_probable_prime(key.q) == COMPOSITE
        # Verify Lagrange's theorem for sub-group
        fmt_error |= ((key.p - 1) % key.q) != 0
        fmt_error |= key.g <= 1 or key.g >= key.p
        fmt_error |= pow(key.g, key.q, key.p) != 1
        # Public key
        fmt_error |= key.y <= 0 or key.y >= key.p
        if hasattr(key, 'x'):
            fmt_error |= key.x <= 0 or key.x >= key.q
            fmt_error |= pow(key.g, key.x, key.p) != key.y

    if fmt_error:
        raise ValueError("Invalid DSA key components")

    return key

def _importKeyDER(key_data, passphrase, params):
    """Import a DSA key (public or private half), encoded in DER form."""

    try:
        #
        # Dss-Parms  ::=  SEQUENCE  {
        #       p       OCTET STRING,
        #       q       OCTET STRING,
        #       g       OCTET STRING
        # }
        #

        # Try a simple private key first
        if params:
            x = DerInteger().decode(key_data).value
            p, q, g = list(DerSequence().decode(params))    # Dss-Parms
            tup = (pow(g, x, p), g, p, q, x)
            return construct(tup)

        der = DerSequence().decode(key_data)

        # Try OpenSSL format for private keys
        if len(der) == 6 and der.hasOnlyInts() and der[0] == 0:
            tup = [der[comp] for comp in (4, 3, 1, 2, 5)]
            return construct(tup)

        # Try SubjectPublicKeyInfo
        if len(der) == 2:
            try:
                algo = DerSequence().decode(der[0])
                algo_oid = DerObjectId().decode(algo[0]).value
                params = DerSequence().decode(algo[1])  # Dss-Parms

                if algo_oid == oid and len(params) == 3 and\
                        params.hasOnlyInts():
                    bitmap = DerBitString().decode(der[1])
                    pub_key = DerInteger().decode(bitmap.value)
                    tup = [pub_key.value]
                    tup += [params[comp] for comp in (2, 0, 1)]
                    return construct(tup)
            except (ValueError, EOFError):
                pass

        # Try to see if this is an X.509 DER certificate
        # (Certificate ASN.1 type)
        if len(der) == 3:
            from Crypto.PublicKey import _extract_sp_info
            try:
                sp_info = _extract_sp_info(der)
                return _importKeyDER(sp_info, passphrase, None)
            except ValueError:
                pass

        # Try unencrypted PKCS#8
        p8_pair = PKCS8.unwrap(key_data, passphrase)
        if p8_pair[0] == oid:
            return _importKeyDER(p8_pair[1], passphrase, p8_pair[2])

    except (ValueError, EOFError):
        pass

    raise ValueError("DSA key format is not supported")

def importKey(extern_key, passphrase=None):
    """Import a DSA key (public or private).

    :Parameters:
      extern_key : (byte) string
        The DSA key to import.

        An DSA *public* key can be in any of the following formats:

        - X.509 certificate (binary or PEM format)
        - X.509 ``subjectPublicKeyInfo`` (binary or PEM)
        - OpenSSH (one line of text, see `RFC4253`_)

        A DSA *private* key can be in any of the following formats:

        - `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
          DER SEQUENCE (binary or PEM encoding)
        - OpenSSL/OpenSSH (binary or PEM)

        For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

        The private key may be encrypted by means of a certain pass phrase
        either at the PEM level or at the PKCS#8 level.

      passphrase : string
        In case of an encrypted private key, this is the pass phrase
        from which the decryption key is derived.

    :Return: A DSA key object (`DsaKey`).
    :Raise ValueError:
        When the given key cannot be parsed (possibly because
        the pass phrase is wrong).

    .. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
    .. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
    .. _RFC4253: http://www.ietf.org/rfc/rfc4253.txt
    .. _PKCS#8: http://www.ietf.org/rfc/rfc5208.txt
    """

    extern_key = tobytes(extern_key)
    if passphrase is not None:
        passphrase = tobytes(passphrase)

    if extern_key.startswith(b('-----')):
        # This is probably a PEM encoded key
        (der, marker, enc_flag) = PEM.decode(tostr(extern_key), passphrase)
        if enc_flag:
            passphrase = None
        return _importKeyDER(der, passphrase, None)

    if extern_key.startswith(b('ssh-dss ')):
        # This is probably a public OpenSSH key
        keystring = binascii.a2b_base64(extern_key.split(b(' '))[1])
        keyparts = []
        while len(keystring) > 4:
            length = struct.unpack(">I", keystring[:4])[0]
            keyparts.append(keystring[4:4 + length])
            keystring = keystring[4 + length:]
        if keyparts[0] == b("ssh-dss"):
            tup = [Integer.from_bytes(keyparts[x]) for x in (4, 3, 1, 2)]
            return construct(tup)

    if bord(extern_key[0]) == 0x30:
        # This is probably a DER encoded key
        return _importKeyDER(extern_key, passphrase, None)

    raise ValueError("DSA key format is not supported")

#: `Object ID`_ for a DSA key.
#:
#: id-dsa ID ::= { iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.10040.4.1.html
oid = "1.2.840.10040.4.1"
