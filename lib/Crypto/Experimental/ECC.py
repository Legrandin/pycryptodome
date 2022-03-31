# ===================================================================
#
# Copyright (c) 2019, Sylvain Pelissier <sylvain.pelissier@gmail.com>
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
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey.ECC import (EccKey, _curves, EccPoint)
from Crypto.Util.asn1 import (DerObjectId, DerOctetString, DerSequence,
                              DerBitString)

from Crypto.Random import get_random_bytes


class EccKeyExplicit(EccKey):
    r"""Class defining an ECC key supporting the explicit curve parameters export.
    """

    def __init__(self, **kwargs):
        EccKey.__init__(self, **kwargs)

    def _export_private_der(self, **kwargs):

        assert self.has_private()

        # ECPrivateKey ::= SEQUENCE {
        #           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        #           privateKey     OCTET STRING,
        #           parameters [0] ECParameters,
        #           publicKey  [1] BIT STRING OPTIONAL
        #    }

        # Public key - uncompressed form
        args = kwargs.copy()
        include_ec_params = args.pop("include_ec_params", True)
        modulus_bytes = self.pointQ.size_in_bytes()
        public_key = (b'\x04' +
                      self.pointQ.x.to_bytes(modulus_bytes) +
                      self.pointQ.y.to_bytes(modulus_bytes))

        order = int(self._curve.order)
        p = int(self._curve.p)
        generator = (b'\x04' +
                    self._curve.G.x.to_bytes(modulus_bytes) +
                    self._curve.G.y.to_bytes(modulus_bytes))
        field_parameters =  DerSequence([DerObjectId("1.2.840.10045.1.1"), p])
        parameters = [DerSequence([1, field_parameters,
                    DerSequence([
                        DerOctetString(self._curve.a.to_bytes(modulus_bytes)),
                        DerOctetString(self._curve.b.to_bytes(modulus_bytes))]),
                    DerOctetString(generator),
                order,
            1
        ])]
        seq = [1,
            DerOctetString(self.d.to_bytes(modulus_bytes)),
            DerSequence(parameters, implicit=0),
            DerBitString(public_key, explicit=1)]

        if not include_ec_params:
            del seq[2]

        return DerSequence(seq).encode()

def generate(**kwargs):
    """Generate a new private key on the given curve.

    Args:

      curve (string):
        Mandatory. It must be a curve name defined in :numref:`curve_names`.

      randfunc (callable):
        Optional. The RNG to read randomness from.
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.
    """

    curve_name = kwargs.pop("curve")
    curve = _curves[curve_name]
    randfunc = kwargs.pop("randfunc", get_random_bytes)
    if kwargs:
        raise TypeError("Unknown parameters: " + str(kwargs))

    d = Integer.random_range(min_inclusive=1,
                             max_exclusive=curve.order,
                             randfunc=randfunc)

    return EccKeyExplicit(curve=curve_name, d=d)

def construct(**kwargs):
    """Build a new ECC key (private or public) starting
    from some base components.

    Args:

      curve (string):
        Mandatory. It must be a curve name defined in :numref:`curve_names`.

      d (integer):
        Only for a private key. It must be in the range ``[1..order-1]``.

      point_x (integer):
        Mandatory for a public key. X coordinate (affine) of the ECC point.

      point_y (integer):
        Mandatory for a public key. Y coordinate (affine) of the ECC point.

    Returns:
      :class:`EccKey` : a new ECC key object
    """

    curve_name = kwargs["curve"]
    curve = _curves[curve_name]
    point_x = kwargs.pop("point_x", None)
    point_y = kwargs.pop("point_y", None)

    if "point" in kwargs:
        raise TypeError("Unknown keyword: point")

    if None not in (point_x, point_y):
        # ValueError is raised if the point is not on the curve
        kwargs["point"] = EccPoint(point_x, point_y, curve_name)

    # Validate that the private key matches the public one
    d = kwargs.get("d", None)
    if d is not None and "point" in kwargs:
        pub_key = curve.G * d
        if pub_key.xy != (point_x, point_y):
            raise ValueError("Private and public ECC keys do not match")

    return EccKeyExplicit(**kwargs)