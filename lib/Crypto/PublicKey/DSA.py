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
           '_DSAobj', 'importKey' ]

import binascii
import struct

from Crypto.Util.py3compat import *

from Crypto import Random
from Crypto.IO import PKCS8, PEM
from Crypto.PublicKey import _DSA, _slowmath
from Crypto.Util.number import (
                        bytes_to_long, long_to_bytes,
                        isPrime, getRandomRange
                        )
from Crypto.Util.asn1 import (
                DerObject, DerSequence,
                DerInteger, DerObjectId,
                DerBitString, newDerSequence,
                newDerBitString
                )

try:
    from Crypto.PublicKey import _fastmath
except ImportError:
    _fastmath = None

def _decode_der(obj_class, binstr):
    """Instantiate a DER object class, decode a DER binary string in it,
    and return the object."""
    der = obj_class()
    der.decode(binstr)
    return der

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

class _DSAobj(object):
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

    def __init__(self, implementation, key, randfunc=None):
        self.implementation = implementation
        self.key = key
        if randfunc is None:
            randfunc = Random.new().read
        self._randfunc = randfunc

    def __getattr__(self, attrname):
        if attrname in self._keydata:
            # For backward compatibility, allow the user to get (not set) the
            # DSA key parameters directly from this object.
            return getattr(self.key, attrname)
        else:
            raise AttributeError("%s object has no %r attribute" % (self.__class__.__name__, attrname,))

    def _sign(self, m, k):
        if not self.has_private():
            raise TypeError("DSA public key cannot be used for signing")
        blind_factor = getRandomRange(1, self.key.q, self._randfunc)
        return self.key._sign(long(m), long(k), blind_factor)

    def _verify(self, m, sig):
        (r, s) = map(long, sig)
        return self.key._verify(long(m), r, s)

    def has_private(self):
        return self.key.has_private()

    def size(self):
        return self.key.size()

    def can_encrypt(self):
        return False

    def can_sign(self):
        return True

    def publickey(self):
        return self.implementation.construct((self.key.y, self.key.g, self.key.p, self.key.q))

    def __eq__(self, other):
        if bool(self.has_private()) != bool(other.has_private()):
            return False

        result = True
        for comp in self._keydata:
            result = result and (getattr(self.key, comp, None) ==
                                 getattr(other.key, comp, None))
        return result

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getstate__(self):
        # DSA key is not pickable
        from pickle import PicklingError
        raise PicklingError

    def domain(self):
        """The DSA domain parameters: *p*, *q* and *g*. """

        return (self.key.p, self.key.q, self.key.g)

    def __repr__(self):
        attrs = []
        for k in self._keydata:
            if k == 'p':
                attrs.append("p(%d)" % (self.size()+1,))
            elif hasattr(self.key, k):
                attrs.append(k)
        if self.has_private():
            attrs.append("private")
        # PY3K: This is meant to be text, do not change to bytes (data)
        return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))

    def exportKey(self, format='PEM', pkcs8=None, passphrase=None,
                  protection=None):
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
        if format == 'OpenSSH':
            tup1 = [long_to_bytes(x) for x in (self.p, self.q, self.g, self.y)]

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
                                randfunc=self._randfunc
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
                                passphrase, self._randfunc
                            )
            return tobytes(pem_str)
        raise ValueError("Unknown key format '%s'. Cannot export the DSA key." % format)


class DSAImplementation(object):
    """
    A DSA key factory.

    This class is only internally used to implement the methods of the
    `Crypto.PublicKey.DSA` module.
    """

    def __init__(self, **kwargs):
        """Create a new DSA key factory.

        :Keywords:
         use_fast_math : bool
                                Specify which mathematic library to use:

                                - *None* (default). Use fastest math available.
                                - *True* . Use fast math.
                                - *False* . Use slow math.
         default_randfunc : callable
                                Specify how to collect random data:

                                - *None* (default). Use Random.new().read().
                                - not *None* . Use the specified function directly.
        :Raise RuntimeError:
            When **use_fast_math** =True but fast math is not available.
        """
        use_fast_math = kwargs.get('use_fast_math', None)
        if use_fast_math is None:   # Automatic
            if _fastmath is not None:
                self._math = _fastmath
            else:
                self._math = _slowmath

        elif use_fast_math:     # Explicitly select fast math
            if _fastmath is not None:
                self._math = _fastmath
            else:
                raise RuntimeError("fast math module not available")

        else:   # Explicitly select slow math
            self._math = _slowmath

        # 'default_randfunc' parameter:
        #   None (default) - use Random.new().read
        #   not None       - use the specified function
        self._default_randfunc = kwargs.get('default_randfunc', None)
        self._current_randfunc = None

    def _get_randfunc(self, randfunc):
        if randfunc is not None:
            return randfunc
        elif self._current_randfunc is None:
            self._current_randfunc = Random.new().read
        return self._current_randfunc

    def generate(self, bits, randfunc=None, progress_func=None, domain=None):
        """Randomly generate a fresh, new DSA key.

        :Parameters:

          bits : int
            Key length, or size (in bits) of the DSA modulus *p*.
            It must be a multiple of 64, in the closed interval [512,1024].

          randfunc : callable
            Random number generation function; it accepts a single integer N
            and return a string of random data N bytes long.
            If not specified, the default from ``Crypto.Random`` is used.

          progress_func : callable
            Optional function that will be called with a short string
            containing the key parameter currently being generated.
            It's useful for interactive applications where a user is
            waiting for a key to be generated.

          domain : list
            The DSA domain parameters *p*, *q* and *g* as a list of 3
            integers. If not specified, they are created anew.

        :attention: You should always use a cryptographically secure
            random number generator, such as the one defined in the
            ``Crypto.Random`` module; **don't** just use the
            current time and the ``random`` module.

        :Return: A DSA key object (`_DSAobj`).

        :Raise ValueError:
            When **bits** is too little, too big, or not a multiple of 64.
        """

        # Check against FIPS 186-2, which says that the size of the prime p
        # must be a multiple of 64 bits between 512 and 1024
        for i in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            if bits == 512 + 64*i:
                return self._generate(bits, randfunc, progress_func, domain)

        # The March 2006 draft of FIPS 186-3 also allows 2048 and 3072-bit
        # primes, but only with longer q values.  Since the current DSA
        # implementation only supports a 160-bit q, we don't support larger
        # values.
        raise ValueError("Number of bits in p must be a multiple of 64 between 512 and 1024, not %d bits" % (bits,))

    def _generate(self, bits, randfunc=None, progress_func=None, domain=None):
        rf = self._get_randfunc(randfunc)
        obj = _DSA.generate_py(bits, rf, progress_func, domain)    # TODO: Don't use legacy _DSA module
        key = self._math.dsa_construct(obj.y, obj.g, obj.p, obj.q, obj.x)
        return _DSAobj(self, key)

    def construct(self, tup, consistency_check=True):
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
        :Return: A DSA key object (`_DSAobj`).
        """

        key = self._math.dsa_construct(*map(long, tup))

        fmt_error = False
        if consistency_check:
            # Modulus must be prime
            fmt_error = not isPrime(key.p)
            # Verify Lagrange's theorem for sub-group
            fmt_error |= ((key.p-1) % key.q)!=0
            fmt_error |= key.g<=1 or key.g>=key.p
            fmt_error |= pow(key.g, key.q, key.p)!=1
            # Public key
            fmt_error |= key.y<=0 or key.y>=key.p
            if hasattr(key, 'x'):
                fmt_error |= key.x<=0 or key.x>=key.q
                fmt_error |= pow(key.g, key.x, key.p)!=key.y

        if fmt_error:
            raise ValueError("Invalid DSA key components")

        return _DSAobj(self, key)

    def _importKeyDER(self, key_data, passphrase=None, params=None):
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
                x = _decode_der(DerInteger, key_data).value
                params = _decode_der(DerSequence, params)    # Dss-Parms
                p, q, g = list(params)
                y = pow(g, x, p)
                tup = (y, g, p, q, x)
                return self.construct(tup)

            der = _decode_der(DerSequence, key_data)

            # Try OpenSSL format for private keys
            if len(der) == 6 and der.hasOnlyInts() and der[0] == 0:
                tup = [der[comp] for comp in (4, 3, 1, 2, 5)]
                return self.construct(tup)

            # Try SubjectPublicKeyInfo
            if len(der) == 2:
                try:
                    algo = _decode_der(DerSequence, der[0])
                    algo_oid = _decode_der(DerObjectId, algo[0]).value
                    params = _decode_der(DerSequence, algo[1])  # Dss-Parms

                    if algo_oid == oid and len(params) == 3 and\
                            params.hasOnlyInts():
                        bitmap = _decode_der(DerBitString, der[1])
                        pub_key = _decode_der(DerInteger, bitmap.value)
                        tup = [pub_key.value]
                        tup += [params[comp] for comp in (2, 0, 1)]
                        return self.construct(tup)
                except (ValueError, EOFError):
                    pass

            # Try unencrypted PKCS#8
            p8_pair = PKCS8.unwrap(key_data, passphrase)
            if p8_pair[0] == oid:
                return self._importKeyDER(p8_pair[1], passphrase, p8_pair[2])

        except (ValueError, EOFError):
            pass

        raise ValueError("DSA key format is not supported")

    def importKey(self, extern_key, passphrase=None):
        """Import a DSA key (public or private).

        :Parameters:
          extern_key : (byte) string
            The DSA key to import.

            An DSA *public* key can be in any of the following formats:

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

        :Return: A DSA key object (`_DSAobj`).
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
            return self._importKeyDER(der, passphrase)

        if extern_key.startswith(b('ssh-dss ')):
            # This is probably a public OpenSSH key
            keystring = binascii.a2b_base64(extern_key.split(b(' '))[1])
            keyparts = []
            while len(keystring) > 4:
                length = struct.unpack(">I", keystring[:4])[0]
                keyparts.append(keystring[4:4 + length])
                keystring = keystring[4 + length:]
            if keyparts[0] == b("ssh-dss"):
                tup = [bytes_to_long(keyparts[x]) for x in (4, 3, 1, 2)]
                return self.construct(tup)

        if bord(extern_key[0]) == 0x30:
            # This is probably a DER encoded key
            return self._importKeyDER(extern_key, passphrase)

        raise ValueError("DSA key format is not supported")

#: `Object ID`_ for a DSA key.
#:
#: id-dsa ID ::= { iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.10040.4.1.html
oid = "1.2.840.10040.4.1"

_impl = DSAImplementation()
generate = _impl.generate
construct = _impl.construct
importKey = _impl.importKey

# vim:set ts=4 sw=4 sts=4 expandtab:

