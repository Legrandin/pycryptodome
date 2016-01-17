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


from Crypto.Util.py3compat import bord

from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)

from Crypto.IO import PKCS8
from Crypto.PublicKey import (_expand_subject_public_key_info,
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


# https://www.nsa.gov/ia/_files/nist-routines.pdf
# http://point-at-infinity.org/ecc/nisttv
# http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
# https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
# https://eprint.iacr.org/2013/816.pdf

class EccPoint(object):

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
        if self.is_point_at_infinity():
            raise ValueError("Point at infinity")
        return self._x

    @property
    def y(self):
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

    def __init__(self, **kwargs):
        """Create a new ECC key

        Do not instantiate this object directly.

        Keywords:
          curve : string
            It must be "P-256", "prime256v1" or "secp256r1".
          d : integer
            Only for a private key. It must be in the range [1..order-1].
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
        if not self.has_private():
            raise ValueError("This is not a private ECC key")
        return self._d

    @property
    def pointQ(self):
        if self._point is None:
            self._point = _curve.G * self._d
        return self._point

    def public_key(self):
        return EccKey(curve="P-256", point=self.pointQ)


def generate(**kwargs):
    """Generate a new private key on the given curve.

    :Keywords:
      curve : string
        It must be "P-256", "prime256v1" or "secp256r1".
      randfunc : callable
        The RNG to read randomness from.
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
        It must be present and set to "P-256", "prime256v1" or "secp256r1".
      d : integer
        Only for a private key. It must be in the range [1..order-1].
      point_x : integer
        X coordinate (affine) of the ECC point.
        This value is mandatory in case of a public key.
      point_y : integer
        Y coordinate (affine) of the ECC point.
        This value is mandatory in case of a public key.
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


def _import_der(encoded, passphrase):

    decodings = (
        _import_subjectPublicKeyInfo,
        _import_private_der,
        _import_pkcs8,
        )

    for decoding in decodings:
        try:
            return decoding(encoded, passphrase)
        except (ValueError, TypeError, IndexError):
            pass

    raise ValueError("Not an ECC DER key")


if __name__ == "__main__":
    import time
    d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd

    point = generate(curve="P-256").pointQ
    start = time.time()
    count = 30
    for x in xrange(count):
        _ = point * d
    print (time.time() - start) / count * 1000, "ms"
