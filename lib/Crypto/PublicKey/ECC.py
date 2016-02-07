# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
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

"""Elliptic Curve Cryptography (ECC) algorithms.

ECC_ is a modern and efficient type of public key cryptography.
Its security is based on the difficulty to solve discrete logarithms
on the field defined by specific equations involving points on a curve.

ECC can be used to perform signing/verification and asymmetric
encryption/decryption.

The main benefit of ECC is that the size of a key is significantly smaller
than with other, more traditional algorithms like RSA or DSA.

For instance, consider the security level equivalent to AES128: an RSA
key of similar strength must have a modulus of 3072 bits (therefore the total size
is 768 bytes, comprising modulus and private exponent).
An ECC private needs as little as 256 bits (32 bytes).

This module provides mechanisms for generating new ECC keys, exporting them
using widely supported formats like PEM or DER and importing them back.

**This module currently supports only ECC keys defined over the standard
NIST P-256 curve** (see `FIPS 186-4`_, Section D.1.2.3). More curves will be
added in the future.

The following example demonstrates how to generate a new key, export it,
and subsequentely reload it back into the application:

    >>> from Crypto.PublicKey import ECC
    >>>
    >>> key = ECC.generate(curve='P-256')
    >>> f = open('myprivatekey.pem','wt')
    >>> f.write(key.export_key('PEM'))
    >>> f.close()
    ...
    >>> f = open('myprivatekey.pem','rt')
    >>> key = RSA.import_key(f.read())

The ECC key can be used to perform or verify ECDSA signatures, see
`Crypto.Signature.DSS`.

.. _ECC: http://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
.. _`FIPS 186-4`: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

:undocumented: __package__
"""


import struct
import binascii

from Crypto.Util.py3compat import bord, tobytes, b, tostr, bchr

from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)

from Crypto.IO import PKCS8, PEM
from Crypto.PublicKey import (_expand_subject_public_key_info,
                              _create_subject_public_key_info,
                              _extract_subject_public_key_info)


class _Curve(object):
    pass

_curve = _Curve()
_curve.p = Integer(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffL)
_curve.b = Integer(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
_curve.order = Integer(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
_curve.Gx = Integer(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)
_curve.Gy = Integer(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
_curve.names = ("P-256", "prime256v1", "secp256r1")
_curve.oid = "1.2.840.10045.3.1.7"


class EccPoint(object):
    """A class to abstract a point over an Elliptic Curve.

    :undocumented: __init__, __eq__, __neg__, __iadd__, __add__, __mul__
    """

    def __init__(self, x, y):
        self._x = Integer(x)
        self._y = Integer(y)

        # Buffers
        self._common = Integer(0)
        self._tmp1 = Integer(0)
        self._x3 = Integer(0)
        self._y3 = Integer(0)

    def set(self, point):
        self._x = Integer(point._x)
        self._y = Integer(point._y)
        return self

    def __eq__(self, point):
        return self._x == point._x and self._y == point._y

    def __neg__(self):
        if self.is_point_at_infinity():
            return self.point_at_infinity()
        return EccPoint(self._x, _curve.p - self._y)

    def copy(self):
        return EccPoint(self._x, self._y)

    def is_point_at_infinity(self):
        return not (self._x or self._y)

    @staticmethod
    def point_at_infinity():
        return EccPoint(0, 0)

    @property
    def x(self):
        """The X-coordinate of the ECC point"""
        if self.is_point_at_infinity():
            raise ValueError("Point at infinity")
        return self._x

    @property
    def y(self):
        """The Y-coordinate of the ECC point"""
        if self.is_point_at_infinity():
            raise ValueError("Point at infinity")
        return self._y

    def double(self):
        """Double this point"""

        if not self._y:
            return self.point_at_infinity()

        common = self._common
        tmp1 = self._tmp1
        x3 = self._x3
        y3 = self._y3

        # common = (pow(self._x, 2, _curve.p) * 3 - 3) * (self._y << 1).inverse(_curve.p) % _curve.p
        common.set(self._x)
        common.inplace_pow(2, _curve.p)
        common *= 3
        common -= 3
        tmp1.set(self._y)
        tmp1 <<= 1
        tmp1.inplace_inverse(_curve.p)
        common *= tmp1
        common %= _curve.p

        # x3 = (pow(common, 2, _curve.p) - 2 * self._x) % _curve.p
        x3.set(common)
        x3.inplace_pow(2, _curve.p)
        x3 -= self._x
        x3 -= self._x
        while x3.is_negative():
            x3 += _curve.p

        # y3 = ((self._x - x3) * common - self._y) % _curve.p
        y3.set(self._x)
        y3 -= x3
        y3 *= common
        y3 -= self._y
        y3 %= _curve.p

        self._x.set(x3)
        self._y.set(y3)
        return self

    def __iadd__(self, point):
        """Add a second point to this one"""

        if self.is_point_at_infinity():
            return self.set(point)

        if point.is_point_at_infinity():
            return self

        if self == point:
            return self.double()

        if self._x == point._x:
            return self.set(self.point_at_infinity())

        common = self._common
        tmp1 = self._tmp1
        x3 = self._x3
        y3 = self._y3

        # common = (point._y - self._y) * (point._x - self._x).inverse(_curve.p) % _curve.p
        common.set(point._y)
        common -= self._y
        tmp1.set(point._x)
        tmp1 -= self._x
        tmp1.inplace_inverse(_curve.p)
        common *= tmp1
        common %= _curve.p

        # x3 = (pow(common, 2, _curve.p) - self._x - point._x) % _curve.p
        x3.set(common)
        x3.inplace_pow(2, _curve.p)
        x3 -= self._x
        x3 -= point._x
        while x3.is_negative():
            x3 += _curve.p

        # y3 = ((self._x - x3) * common - self._y) % _curve.p
        y3.set(self._x)
        y3 -= x3
        y3 *= common
        y3 -= self._y
        y3 %= _curve.p

        self._x.set(x3)
        self._y.set(y3)
        return self

    def __add__(self, point):
        """Return a new point, the addition of this one and another"""

        result = self.copy()
        result += point
        return result

    def __mul__(self, scalar):
        """Return a new point, the scalar product of this one"""

        if scalar < 0:
            raise ValueError("Scalar multiplication only defined for non-negative integers")

        # Trivial results
        if scalar == 0 or self.is_point_at_infinity():
            return self.point_at_infinity()
        elif scalar == 1:
            return self.copy()

        # Scalar randomization
        scalar_blind = Integer.random(exact_bits=64) * _curve.order + scalar

        # Montgomery key ladder
        r = [self.point_at_infinity().copy(), self.copy()]
        bit_size = int(scalar_blind.size_in_bits())
        scalar_int = int(scalar_blind)
        for i in range(bit_size, -1, -1):
            di = scalar_int >> i & 1
            r[di ^ 1] += r[di]
            r[di].double()

        return r[0]


_curve.G = EccPoint(_curve.Gx, _curve.Gy)


class EccKey(object):
    """A private or public key over an Elliptic Curve.

    :undocumented: __eq__, __repr__, __init__
    """

    def __init__(self, **kwargs):
        """Create a new ECC key

        Do not instantiate this object directly.

        Keywords:
          curve : string
            It must be *"P-256"*, *"prime256v1"* or *"secp256r1"*.
          d : integer
            Only for a private key. It must be in the range ``[1..order-1]``.
          point : EccPoint
            Mandatory for a public key. If provided for a private key,
            the implementation will NOT check whether it matches ``d``.
        """

        kwargs_ = dict(kwargs)
        self.curve = kwargs_.pop("curve", None)
        self._d = kwargs_.pop("d", None)
        self._point = kwargs_.pop("point", None)
        if kwargs_:
            raise TypeError("Unknown parameters: " + str(kwargs_))

        if self.curve not in _curve.names:
            raise ValueError("Unsupported curve (%s)", self.curve)

        if self._d is None:
            if self._point is None:
                raise ValueError("Either private or public ECC component must be specified")
        else:
            self._d = Integer(self._d)
            if not 1 <= self._d < _curve.order:
                raise ValueError("Invalid ECC private component")

    def __eq__(self, other):
        if other.has_private() != self.has_private():
            return False

        return (other.pointQ.x == self.pointQ.x) and (other.pointQ.y == self.pointQ.y)

    def __repr__(self):
        if self.has_private():
            extra = ", d=%d" % int(self._d)
        else:
            extra = ""
        return "EccKey(curve='P-256', x=%d, y=%d%s)" %\
               (self.pointQ.x, self.pointQ.y, extra)

    def has_private(self):
        """True if this key can be used for making signatures or decrypting"""
        return self._d is not None

    def _sign(self, z, k):
        assert 0 < k < _curve.order

        blind = Integer.random_range(min_inclusive=1,
                                     max_exclusive=_curve.order)

        blind_d = self._d * blind
        inv_blind_k = (blind * k).inverse(_curve.order)

        r = (_curve.G * k).x % _curve.order
        s = inv_blind_k * (blind * z + blind_d * r) % _curve.order
        return (r, s)

    def _verify(self, z, rs):
        sinv = rs[1].inverse(_curve.order)
        point1 = _curve.G * ((sinv * z) % _curve.order)
        point2 = self.pointQ * ((sinv * rs[0]) % _curve.order)
        return (point1 + point2).x == rs[0]

    @property
    def d(self):
        """An integer (scalar), representating the private component"""
        if not self.has_private():
            raise ValueError("This is not a private ECC key")
        return self._d

    @property
    def pointQ(self):
        """An `EccPoint`, representating the public component"""
        if self._point is None:
            self._point = _curve.G * self._d
        return self._point

    def public_key(self):
        """Create a new `EccKey`, by retaining only the public components"""
        return EccKey(curve="P-256", point=self.pointQ)

    def _export_subjectPublicKeyInfo(self):

        # Uncompressed form
        order_bytes = _curve.order.size_in_bytes()
        public_key = (bchr(4) +
                      self.pointQ.x.to_bytes(order_bytes) +
                      self.pointQ.y.to_bytes(order_bytes))

        unrestricted_oid = "1.2.840.10045.2.1"
        return _create_subject_public_key_info(unrestricted_oid,
                                               public_key,
                                               DerObjectId(_curve.oid))

    def _export_private_der(self, include_ec_params=True):

        assert self.has_private()

        # ECPrivateKey ::= SEQUENCE {
        #           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        #           privateKey     OCTET STRING,
        #           parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        #           publicKey  [1] BIT STRING OPTIONAL
        #    }

        # Public key - uncompressed form
        order_bytes = _curve.order.size_in_bytes()
        public_key = (bchr(4) +
                      self.pointQ.x.to_bytes(order_bytes) +
                      self.pointQ.y.to_bytes(order_bytes))

        seq = [1,
               DerOctetString(self.d.to_bytes(order_bytes)),
               DerObjectId(_curve.oid, explicit=0),
               DerBitString(public_key, explicit=1)]

        if not include_ec_params:
            del seq[2]

        return DerSequence(seq).encode()

    def _export_pkcs8(self, **kwargs):
        if kwargs.get('passphrase', None) is not None and 'protection' not in kwargs:
            raise ValueError("At least the 'protection' parameter should be present")
        unrestricted_oid = "1.2.840.10045.2.1"
        private_key = self._export_private_der(include_ec_params=False)
        result = PKCS8.wrap(private_key,
                            unrestricted_oid,
                            key_params=DerObjectId(_curve.oid),
                            **kwargs)
        return result

    def _export_public_pem(self):
        encoded_der = self._export_subjectPublicKeyInfo()
        return PEM.encode(encoded_der, "PUBLIC KEY")

    def _export_private_pem(self, passphrase, **kwargs):
        encoded_der = self._export_private_der()
        return PEM.encode(encoded_der, "EC PRIVATE KEY", passphrase, **kwargs)

    def _export_private_clear_pkcs8_in_clear_pem(self):
        encoded_der = self._export_pkcs8()
        return PEM.encode(encoded_der, "PRIVATE KEY")

    def _export_private_encrypted_pkcs8_in_clear_pem(self, passphrase, **kwargs):
        assert passphrase
        if 'protection' not in kwargs:
            raise ValueError("At least the 'protection' parameter should be present")
        encoded_der = self._export_pkcs8(passphrase=passphrase, **kwargs)
        return PEM.encode(encoded_der, "ENCRYPTED PRIVATE KEY")

    def _export_openssh(self):
        assert not self.has_private()

        desc = "ecdsa-sha2-nistp256"

        # Uncompressed form
        order_bytes = _curve.order.size_in_bytes()
        public_key = (bchr(4) +
                      self.pointQ.x.to_bytes(order_bytes) +
                      self.pointQ.y.to_bytes(order_bytes))

        comps = (tobytes(desc), b("nistp256"), public_key)
        blob = b("").join([ struct.pack(">I", len(x)) + x for x in comps])
        return desc + " " + tostr(binascii.b2a_base64(blob))

    def export_key(self, **kwargs):
        """Export this ECC key.

        :Keywords:

          format : string
            The format to use for wrapping the key:

            - *'DER'*. The key will be encoded in an ASN.1 DER_ structure (binary).
            - *'PEM'*. The key will be encoded in a PEM_ envelope (ASCII).
            - *'OpenSSH'*. The key will be encoded in the OpenSSH_ format
              (ASCII, public keys only).

          passphrase : byte string or string
            The passphrase to use for protecting the private key.
            *If not provided, the private key will remain in clear form!*

          use_pkcs8 : boolean
            In case of a private key, whether the PKCS#8_ representation
            should be (internally) used. By default it will.

            Not using PKCS#8 when exporting a private key in
            password-protected PEM_ form means that the much weaker and
            unflexible `PEM encryption`_ mechanism will be used.
            PKCS#8 is therefore always recommended.

          protection : string
            In case of a private key being exported with password-protection
            and PKCS#8 (both ``DER`` and ``PEM`` formats), this parameter MUST be
            present and be a valid algorithm supported by `Crypto.IO.PKCS8`.
            It is recommended to use ``PBKDF2WithHMAC-SHA1AndAES128-CBC``.

        :Note:
            In case of a private key being exported with password-protection
            and PKCS#8_ (both ``DER`` and ``PEM`` formats), all additional parameters
            will be passed to `Crypto.IO.PKCS8`.

        .. _DER:        http://www.ietf.org/rfc/rfc5915.txt
        .. _PEM:        http://www.ietf.org/rfc/rfc1421.txt
        .. _`PEM encryption`: http://www.ietf.org/rfc/rfc1423.txt
        .. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
        .. _OpenSSH:    http://www.openssh.com/txt/rfc5656.txt

        :Return: A multi-line string (for PEM and OpenSSH) or bytes (for DER) with the encoded key.
        """

        args = kwargs.copy()
        ext_format = args.pop("format")
        if ext_format not in ("PEM", "DER", "OpenSSH"):
            raise ValueError("Unknown format '%s'" % ext_format)

        if self.has_private():
            passphrase = args.pop("passphrase", None)
            if isinstance(passphrase, basestring):
                passphrase = tobytes(passphrase)
                if not passphrase:
                    raise ValueError("Empty passphrase")
            use_pkcs8 = args.pop("use_pkcs8", True)
            if ext_format == "PEM":
                if use_pkcs8:
                    if passphrase:
                        return self._export_private_encrypted_pkcs8_in_clear_pem(passphrase, **args)
                    else:
                        return self._export_private_clear_pkcs8_in_clear_pem()
                else:
                    return self._export_private_pem(passphrase, **args)
            elif ext_format == "DER":
                # DER
                if passphrase and not use_pkcs8:
                    raise ValueError("Private keys can only be encrpyted with DER using PKCS#8")
                if use_pkcs8:
                    return self._export_pkcs8(passphrase=passphrase, **args)
                else:
                    return self._export_private_der()
            else:
                raise ValueError("Private keys cannot be exported in OpenSSH format")
        else:  # Public key
            if args:
                raise ValueError("Unexpected parameters: '%s'" % args)
            if ext_format == "PEM":
                return self._export_public_pem()
            elif ext_format == "DER":
                return self._export_subjectPublicKeyInfo()
            else:
                return self._export_openssh()


def generate(**kwargs):
    """Generate a new private key on the given curve.

    :Keywords:
      curve : string
        Mandatory. It must be "P-256", "prime256v1" or "secp256r1".
      randfunc : callable
        Optional. The RNG to read randomness from.
        If ``None``, the system source is used.
    """

    curve = kwargs.pop("curve")
    randfunc = kwargs.pop("randfunc", get_random_bytes)
    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    d = Integer.random_range(min_inclusive=1,
                             max_exclusive=_curve.order,
                             randfunc=randfunc)

    return EccKey(curve=curve, d=d)


def construct(**kwargs):
    """Build a new ECC key (private or public) starting
    from some base components.

    :Keywords:
      curve : string
        Mandatory. It must be "P-256", "prime256v1" or "secp256r1".
      d : integer
        Only for a private key. It must be in the range ``[1..order-1]``.
      point_x : integer
        Mandatory for a public key. X coordinate (affine) of the ECC point.
      point_y : integer
        Mandatory for a public key. Y coordinate (affine) of the ECC point.
    """

    point_x = kwargs.pop("point_x", None)
    point_y = kwargs.pop("point_y", None)

    if "point" in kwargs:
        raise TypeError("Unknown keyword: point")

    if None not in (point_x, point_y):
        kwargs["point"] = EccPoint(point_x, point_y)

        # Validate that the point is on the P-256 curve
        eq1 = pow(Integer(point_y), 2, _curve.p)
        x = Integer(point_x)
        eq2 = pow(x, 3, _curve.p)
        x *= -3
        eq2 += x
        eq2 += _curve.b
        eq2 %= _curve.p

        if eq1 != eq2:
            raise ValueError("The point is not on the curve")

    # Validate that the private key matches the public one
    d = kwargs.get("d", None)
    if d is not None and "point" in kwargs:
        pub_key = _curve.G * d
        if pub_key.x != point_x or pub_key.y != point_y:
            raise ValueError("Private and public ECC keys do not match")

    return EccKey(**kwargs)


def _import_public_der(curve_name, publickey):

    # We only support P-256 named curves for now
    if curve_name != _curve.oid:
        raise ValueError("Unsupport curve")

    # ECPoint ::= OCTET STRING

    # We support only uncompressed points
    order_bytes = _curve.order.size_in_bytes()
    if len(publickey) != (1 + 2 * order_bytes) or bord(publickey[0]) != 4:
        raise ValueError("Only uncompressed points are supported")

    point_x = Integer.from_bytes(publickey[1:order_bytes+1])
    point_y = Integer.from_bytes(publickey[order_bytes+1:])
    return construct(curve="P-256", point_x=point_x, point_y=point_y)


def _import_subjectPublicKeyInfo(encoded, *kwargs):
    oid, encoded_key, params = _expand_subject_public_key_info(encoded)

    # We accept id-ecPublicKey, id-ecDH, id-ecMQV without making any
    # distiction for now.
    unrestricted_oid = "1.2.840.10045.2.1"
    ecdh_oid = "1.3.132.1.12"
    ecmqv_oid = "1.3.132.1.13"

    if oid not in (unrestricted_oid, ecdh_oid, ecmqv_oid) or not params:
        raise ValueError("Invalid ECC OID")

    # ECParameters ::= CHOICE {
    #   namedCurve         OBJECT IDENTIFIER
    #   -- implicitCurve   NULL
    #   -- specifiedCurve  SpecifiedECDomain
    # }
    curve_name = DerObjectId().decode(params).value

    return _import_public_der(curve_name, encoded_key)


def _import_private_der(encoded, passphrase, curve_name=None):

    # ECPrivateKey ::= SEQUENCE {
    #           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    #           privateKey     OCTET STRING,
    #           parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    #           publicKey  [1] BIT STRING OPTIONAL
    #    }

    private_key = DerSequence().decode(encoded, nr_elements=(3, 4))
    if private_key[0] != 1:
        raise ValueError("Incorrect ECC private key version")

    scalar_bytes = DerOctetString().decode(private_key[1]).payload
    order_bytes = _curve.order.size_in_bytes()
    if len(scalar_bytes) != order_bytes:
        raise ValueError("Private key is too small")
    d = Integer.from_bytes(scalar_bytes)

    try:
        curve_name = DerObjectId(explicit=0).decode(private_key[2]).value
    except ValueError:
        pass

    if curve_name != _curve.oid:
        raise ValueError("Unsupport curve")

    # Decode public key (if any, it must be P-256)
    if len(private_key) == 4:
        public_key_enc = DerBitString(explicit=1).decode(private_key[3]).value
        public_key = _import_public_der(curve_name, public_key_enc)
        point_x = public_key.pointQ.x
        point_y = public_key.pointQ.y
    else:
        point_x = point_y = None

    return construct(curve="P-256", d=d, point_x=point_x, point_y=point_y)


def _import_pkcs8(encoded, passphrase):

    # From RFC5915, Section 1:
    #
    # Distributing an EC private key with PKCS#8 [RFC5208] involves including:
    # a) id-ecPublicKey, id-ecDH, or id-ecMQV (from [RFC5480]) with the
    #    namedCurve as the parameters in the privateKeyAlgorithm field; and
    # b) ECPrivateKey in the PrivateKey field, which is an OCTET STRING.

    algo_oid, private_key, params = PKCS8.unwrap(encoded, passphrase)

    # We accept id-ecPublicKey, id-ecDH, id-ecMQV without making any
    # distiction for now.
    unrestricted_oid = "1.2.840.10045.2.1"
    ecdh_oid = "1.3.132.1.12"
    ecmqv_oid = "1.3.132.1.13"

    if algo_oid not in (unrestricted_oid, ecdh_oid, ecmqv_oid):
        raise ValueError("No PKCS#8 encoded ECC key")

    curve_name = DerObjectId().decode(params).value

    return _import_private_der(private_key, passphrase, curve_name)


def _import_x509_cert(encoded, *kwargs):

    sp_info = _extract_subject_public_key_info(encoded)
    return _import_subjectPublicKeyInfo(sp_info)


def _import_der(encoded, passphrase):

    decodings = (
        _import_subjectPublicKeyInfo,
        _import_x509_cert,
        _import_private_der,
        _import_pkcs8,
        )

    for decoding in decodings:
        try:
            return decoding(encoded, passphrase)
        except (ValueError, TypeError, IndexError):
            pass

    raise ValueError("Not an ECC DER key")


def _import_openssh(encoded):
    keystring = binascii.a2b_base64(encoded.split(b(' '))[1])

    keyparts = []
    while len(keystring) > 4:
        l = struct.unpack(">I", keystring[:4])[0]
        keyparts.append(keystring[4:4 + l])
        keystring = keystring[4 + l:]

    if keyparts[1] != b("nistp256"):
        raise ValueError("Unsupported ECC curve")

    return _import_public_der(_curve.oid, keyparts[2])


def import_key(encoded, passphrase=None):
    """Import an ECC key (public or private).

    :Parameters:
      encoded : bytes or a (multi-line) string
        The ECC key to import.

        An ECC public key can be:

        - An X.509 certificate, binary (DER) or ASCII (PEM)
        - An X.509 ``subjectPublicKeyInfo``, binary (DER) or ASCII (PEM)
        - An OpenSSH line (e.g. the content of ``~/.ssh/id_ecdsa``, ASCII)

        An ECC private key can be:

        - In binary format (DER, see section 3 of `RFC5915`_ or `PKCS#8`_)
        - In ASCII format (PEM or OpenSSH)

        Private keys can be in the clear or password-protected.

        For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

    :Keywords:
      passphrase : byte string
        The passphrase to use for decrypting a private key.
        Encryption may be applied protected at the PEM level or at the PKCS#8 level.
        This parameter is ignored if the key in input is not encrypted.

    :Return: An ECC key object (`EccKey`)

    :Raise ValueError:
        When the given key cannot be parsed (possibly because
        the pass phrase is wrong).

    .. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
    .. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
    .. _RFC5915: http://www.ietf.org/rfc/rfc5915.txt
    .. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt
    """

    encoded = tobytes(encoded)
    if passphrase is not None:
        passphrase = tobytes(passphrase)

    # PEM
    if encoded.startswith(b('-----')):
        der_encoded, marker, enc_flag = PEM.decode(tostr(encoded), passphrase)
        if enc_flag:
            passphrase = None
        return _import_der(der_encoded, passphrase)

    # OpenSSH
    if encoded.startswith(b('ecdsa-sha2-')):
        return _import_openssh(encoded)

    # DER
    if bord(encoded[0]) == 0x30:
        return _import_der(encoded, passphrase)

    raise ValueError("ECC key format is not supported")


if __name__ == "__main__":
    import time
    d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd

    point = generate(curve="P-256").pointQ
    start = time.time()
    count = 30
    for x in xrange(count):
        _ = point * d
    print (time.time() - start) / count * 1000, "ms"
