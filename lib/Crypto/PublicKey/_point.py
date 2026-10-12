# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from __future__ import annotations

import importlib
import threading
from typing import Any, Optional, TypeVar, Union

from Crypto.Math._IntegerBase import IntegerBase
from Crypto.Math.Numbers import Integer
from Crypto.Random.random import getrandbits
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    c_ulonglong,
    null_pointer,
)
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ._curve import _Curve

# EccPoint or EccXPoint (defined below)
_PointT = TypeVar("_PointT", "EccPoint", "EccXPoint")


def _encode_coordinate(value: Union[int, IntegerBase], length: int) -> bytes:
    """Encode a coordinate into exactly ``length`` bytes (big endian)"""

    if isinstance(value, IntegerBase):
        try:
            return value.to_bytes(length)
        except ValueError:
            raise ValueError("Incorrect coordinate length")
    encoded = long_to_bytes(int(value), length)
    if len(encoded) != length:
        raise ValueError("Incorrect coordinate length")
    return encoded


def _encode_scalar(scalar: Union[int, IntegerBase], min_length: int) -> bytes:
    """Encode a scalar (big endian).

    An Integer (possibly secret) is encoded with ``min_length`` bytes,
    so that its actual length does not leak. Only a longer one needs more.
    """

    if isinstance(scalar, IntegerBase):
        try:
            return scalar.to_bytes(min_length)
        except ValueError:
            return scalar.to_bytes()
    return long_to_bytes(scalar)


def _curve_context(curve: _Curve) -> Any:
    """The context of the C code of a curve (a null pointer if it has none).

    The type of the pointer depends on the FFI backend (cffi or ctypes).
    """

    return null_pointer if curve.context is None else curve.context.get()


def _clone_raw_point(curve: _Curve, point: Union[EccPoint, EccXPoint]) -> SmartPointer:
    """A copy of the C point of an EccPoint or EccXPoint (on curve)"""

    raw_point = VoidPointer()
    result = curve.rawlib.clone(raw_point.address_of(), point._point.get())
    if result:
        raise ValueError("Error %d while cloning an EC point" % result)
    return SmartPointer(raw_point.get(), curve.rawlib.free_point)


def _copy_point(point: _PointT) -> _PointT:
    """A copy of an EccPoint or EccXPoint, of the same class"""

    copy = point.__class__.__new__(point.__class__)
    copy._curve = point._curve
    copy.curve = point.curve
    copy._point = _clone_raw_point(point._curve, point)
    return copy


class CurveID:
    P192 = 1
    P224 = 2
    P256 = 3
    P384 = 4
    P521 = 5
    ED25519 = 6
    ED448 = 7
    CURVE25519 = 8
    CURVE448 = 9


_nist_curve_ids = (CurveID.P192, CurveID.P224, CurveID.P256, CurveID.P384, CurveID.P521)


class _Curves:
    curves: dict[str, Any] = {}
    curves_lock = threading.RLock()

    p192_names = ["p192", "NIST P-192", "P-192", "prime192v1", "secp192r1", "nistp192"]
    p224_names = ["p224", "NIST P-224", "P-224", "prime224v1", "secp224r1", "nistp224"]
    p256_names = ["p256", "NIST P-256", "P-256", "prime256v1", "secp256r1", "nistp256"]
    p384_names = ["p384", "NIST P-384", "P-384", "prime384v1", "secp384r1", "nistp384"]
    p521_names = ["p521", "NIST P-521", "P-521", "prime521v1", "secp521r1", "nistp521"]
    ed25519_names = ["ed25519", "Ed25519"]
    ed448_names = ["ed448", "Ed448"]
    curve25519_names = ["curve25519", "Curve25519", "X25519"]
    curve448_names = ["curve448", "Curve448", "X448"]

    # For each curve: its names, its ID, and the module and function that create it
    definitions = (
        (p192_names, CurveID.P192, "_nist_ecc", "p192_curve"),
        (p224_names, CurveID.P224, "_nist_ecc", "p224_curve"),
        (p256_names, CurveID.P256, "_nist_ecc", "p256_curve"),
        (p384_names, CurveID.P384, "_nist_ecc", "p384_curve"),
        (p521_names, CurveID.P521, "_nist_ecc", "p521_curve"),
        (ed25519_names, CurveID.ED25519, "_edwards", "ed25519_curve"),
        (ed448_names, CurveID.ED448, "_edwards", "ed448_curve"),
        (curve25519_names, CurveID.CURVE25519, "_montgomery", "curve25519_curve"),
        (curve448_names, CurveID.CURVE448, "_montgomery", "curve448_curve"),
    )

    all_names = [name for definition in definitions for name in definition[0]]

    def __contains__(self, item):
        return item in self.all_names

    def __dir__(self):
        return self.all_names

    def load(self, name):
        definition = next((d for d in self.definitions if name in d[0]), None)
        if definition is None:
            raise ValueError("Unsupported curve '%s'" % name)
        names, curve_id, module_name, function = definition
        module = importlib.import_module("." + module_name, __package__)
        curve = getattr(module, function)()
        curve.id = curve_id
        self.curves.update(dict.fromkeys(names, curve))
        return curve

    def __getitem__(self, name):
        with self.curves_lock:
            curve = self.curves.get(name)
            if curve is None:
                curve = self.load(name)
                if name in self.curve25519_names or name in self.curve448_names:
                    curve.G = EccXPoint(curve.Gx, name)
                else:
                    curve.G = EccPoint(curve.Gx, curve.Gy, name)
                curve.is_edwards = curve.id in (CurveID.ED25519, CurveID.ED448)
                curve.is_montgomery = curve.id in (CurveID.CURVE25519, CurveID.CURVE448)
                curve.is_weierstrass = not (curve.is_edwards or curve.is_montgomery)
        return curve

    def items(self):
        # Load all curves
        for name in self.all_names:
            _ = self[name]
        return self.curves.items()


_curves = _Curves()


class EccPoint:
    """A class to model a point on an Elliptic Curve.

    The class supports operators for:

    * Adding two points: ``R = S + T``
    * In-place addition: ``S += T``
    * Negating a point: ``R = -T``
    * Comparing two points: ``if S == T: ...`` or ``if S != T: ...``
    * Multiplying a point by a scalar: ``R = S*k``
    * In-place multiplication by a scalar: ``T *= k``

    :ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
    :vartype curve: string

    :ivar x: The affine X-coordinate of the ECC point
    :vartype x: integer

    :ivar y: The affine Y-coordinate of the ECC point
    :vartype y: integer

    :ivar xy: The tuple with affine X- and Y- coordinates
    """

    def __init__(self, x: Union[int, Integer], y: Union[int, Integer], curve: Optional[str] = "p256") -> None:
        try:
            self._curve = _curves[curve]
        except KeyError:
            raise ValueError("Unknown curve name %s" % str(curve))
        self.curve = self._curve.canonical

        if self._curve.id == CurveID.CURVE25519:
            raise ValueError("EccPoint cannot be created for Curve25519")

        modulus_bytes = self.size_in_bytes()

        xb = _encode_coordinate(x, modulus_bytes)
        yb = _encode_coordinate(y, modulus_bytes)

        # For the NIST curves, coordinates that fit in the length of the
        # modulus are reduced modulo p (the C code only accepts values
        # smaller than p). Imported keys are checked before, and they are
        # rejected instead (see ECC._import_public_der).
        if self._curve.id in _nist_curve_ids:
            p = int(self._curve.p)
            xb = long_to_bytes(bytes_to_long(xb) % p, modulus_bytes)
            yb = long_to_bytes(bytes_to_long(yb) % p, modulus_bytes)

        new_point = self._curve.rawlib.new_point
        free_func = self._curve.rawlib.free_point

        raw_point = VoidPointer()
        context = _curve_context(self._curve)
        result = new_point(
            raw_point.address_of(), c_uint8_ptr(xb), c_uint8_ptr(yb), c_size_t(modulus_bytes), context
        )

        if result:
            if result == 15:
                raise ValueError("The EC point does not belong to the curve")
            raise ValueError("Error %d while instantiating an EC point" % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the EC point
        self._point = SmartPointer(raw_point.get(), free_func)

    @classmethod
    def _decode_eddsa(cls, encoded: bytes, curve: str) -> EccPoint:
        """A point of Ed25519 or Ed448, from its encoding in RFC 8032.

        Raises ValueError if the encoding is not valid.
        """

        point = cls.__new__(cls)
        point._curve = _curves[curve]
        point.curve = point._curve.canonical

        raw_point = VoidPointer()
        context = _curve_context(point._curve)
        result = point._curve.rawlib.decode_point(
            raw_point.address_of(), c_uint8_ptr(encoded), c_size_t(len(encoded)), context
        )
        if result:
            raise ValueError("Invalid %s point encoding" % point.curve)
        point._point = SmartPointer(raw_point.get(), point._curve.rawlib.free_point)
        return point

    def set(self, point: EccPoint) -> EccPoint:
        self._point = _clone_raw_point(self._curve, point)
        return self

    def __eq__(self, point: object) -> bool:
        if not isinstance(point, EccPoint):
            return False

        cmp_func = self._curve.rawlib.cmp
        return cmp_func(self._point.get(), point._point.get()) == 0

    def __neg__(self) -> EccPoint:
        neg_func = self._curve.rawlib.neg
        np = self.copy()
        result = neg_func(np._point.get())
        if result:
            raise ValueError("Error %d while inverting an EC point" % result)
        return np

    def copy(self) -> EccPoint:
        """Return a copy of this point."""

        return _copy_point(self)

    def is_point_at_infinity(self) -> bool:
        """``True`` if this is the *point-at-infinity*."""

        # Compared in C, as the point may be secret (ECDH): only the result leaks
        return self == self.point_at_infinity()

    def point_at_infinity(self) -> EccPoint:
        """Return the *point-at-infinity* for the curve."""

        if self._curve.is_edwards:
            return EccPoint(0, 1, self.curve)
        else:
            return EccPoint(0, 0, self.curve)

    @property
    def x(self) -> int:
        return self.xy[0]

    @property
    def y(self) -> int:
        return self.xy[1]

    @property
    def xy(self) -> tuple[int, int]:
        xb, yb = self._get_xy_bytes()
        return (bytes_to_long(xb), bytes_to_long(yb))

    # The coordinates as Integer objects, for the library itself.
    # The conversion is constant time (the point may be secret, as in ECDH).

    @property
    def _x(self) -> Integer:
        return self._xy[0]

    @property
    def _y(self) -> Integer:
        return self._xy[1]

    @property
    def _xy(self) -> tuple[Integer, Integer]:
        xb, yb = self._get_xy_bytes()
        return (Integer.from_bytes(xb), Integer.from_bytes(yb))

    def _get_xy_bytes(self) -> tuple[bytearray, bytearray]:
        modulus_bytes = self.size_in_bytes()
        xb = bytearray(modulus_bytes)
        yb = bytearray(modulus_bytes)
        get_xy = self._curve.rawlib.get_xy
        with c_uint8_ptr_out(xb) as xb_ptr, c_uint8_ptr_out(yb) as yb_ptr:
            result = get_xy(xb_ptr, yb_ptr, c_size_t(modulus_bytes), self._point.get())
        if result:
            raise ValueError("Error %d while encoding an EC point" % result)
        return xb, yb

    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits

    def double(self) -> EccPoint:
        """Double this point (in-place operation).

        Returns:
            This same object (to enable chaining).
        """

        double_func = self._curve.rawlib.double
        result = double_func(self._point.get())
        if result:
            raise ValueError("Error %d while doubling an EC point" % result)
        return self

    def __iadd__(self, point: EccPoint) -> EccPoint:
        """Add a second point to this one"""

        # Not all the C modules check it (Ed25519)
        if self._curve is not point._curve:
            raise ValueError("EC points are not on the same curve")
        add_func = self._curve.rawlib.add
        result = add_func(self._point.get(), point._point.get())
        if result:
            if result == 16:
                raise ValueError("EC points are not on the same curve")
            raise ValueError("Error %d while adding two EC points" % result)
        return self

    def __add__(self, point: EccPoint) -> EccPoint:
        """Return a new point, the addition of this one and another"""

        np = self.copy()
        np += point
        return np

    def __imul__(self, scalar: int) -> EccPoint:
        """Multiply this point by a scalar.

        The scalar is treated as secret, unless it is an Integer created as public.
        """

        if scalar < 0:
            raise ValueError("Scalar multiplication is only defined for non-negative integers")

        # A public scalar: no blinding, and only as many bits as needed
        public_func = getattr(self._curve.rawlib, "scalar_public", None)
        if public_func is not None and isinstance(scalar, IntegerBase) and scalar._public:
            sb = scalar.to_bytes()
            sb_ptr, sb_len = c_uint8_ptr_len(sb)
            result = public_func(self._point.get(), sb_ptr, c_size_t(sb_len))
        else:
            sb = _encode_scalar(scalar, self.size_in_bytes())
            sb_ptr, sb_len = c_uint8_ptr_len(sb)
            result = self._curve.rawlib.scalar(
                self._point.get(), sb_ptr, c_size_t(sb_len), c_ulonglong(getrandbits(64))
            )
        if result:
            raise ValueError("Error %d during scalar multiplication" % result)
        return self

    def __mul__(self, scalar: int) -> EccPoint:
        """Return a new point, the scalar product of this one"""

        np = self.copy()
        np *= scalar
        return np

    def __rmul__(self, left_hand):
        return self.__mul__(left_hand)


class EccXPoint:
    """A class to model a point on an Elliptic Curve,
    where only the X-coordinate is exposed.

    The class supports operators for:

    * Multiplying a point by a scalar: ``R = S*k``
    * In-place multiplication by a scalar: ``T *= k``

    :ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
    :vartype curve: string

    :ivar x: The affine X-coordinate of the ECC point
    :vartype x: integer
    """

    def __init__(self, x: Optional[Union[int, Integer]], curve: Optional[str]) -> None:
        # Once encoded, x must not exceed the length of the modulus,
        # but its value may match or exceed the modulus itself
        # (i.e., non-canonical value)

        try:
            self._curve = _curves[curve]
        except KeyError:
            raise ValueError("Unknown curve name %s" % str(curve))
        self.curve = self._curve.canonical

        if self._curve.id not in (CurveID.CURVE25519, CurveID.CURVE448):
            raise ValueError("EccXPoint can only be created for Curve25519/Curve448")

        new_point = self._curve.rawlib.new_point
        free_func = self._curve.rawlib.free_point

        context = _curve_context(self._curve)

        modulus_bytes = self.size_in_bytes()

        if x is None:
            xb = null_pointer
        else:
            xb = c_uint8_ptr(_encode_coordinate(x, modulus_bytes))

        raw_point = VoidPointer()
        result = new_point(raw_point.address_of(), xb, c_size_t(modulus_bytes), context)

        if result == 15:
            raise ValueError("The EC point does not belong to the curve")
        if result:
            raise ValueError("Error %d while instantiating an EC point" % result)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the EC point
        self._point = SmartPointer(raw_point.get(), free_func)

    def set(self, point: EccXPoint) -> EccXPoint:
        self._point = _clone_raw_point(self._curve, point)
        return self

    def __eq__(self, point: object) -> bool:
        if not isinstance(point, EccXPoint):
            return False

        cmp_func = self._curve.rawlib.cmp
        p1 = self._point.get()
        p2 = point._point.get()
        res = cmp_func(p1, p2)
        return res == 0

    def copy(self) -> EccXPoint:
        """Return a copy of this point."""

        return _copy_point(self)

    def is_point_at_infinity(self) -> bool:
        """``True`` if this is the *point-at-infinity*."""

        # The x coordinate stays in bytes, as the point may be secret (ECDH):
        # only the result leaks
        try:
            self._get_x_bytes()
        except ValueError:
            return True
        return False

    def point_at_infinity(self) -> EccXPoint:
        """Return the *point-at-infinity* for the curve."""

        return EccXPoint(None, self.curve)

    @property
    def x(self) -> int:
        return bytes_to_long(self._get_x_bytes())

    @property
    def _x(self) -> Integer:
        """The X coordinate as an Integer, converted in constant time"""
        return Integer.from_bytes(self._get_x_bytes())

    def _get_x_bytes(self) -> bytearray:
        modulus_bytes = self.size_in_bytes()
        xb = bytearray(modulus_bytes)
        get_x = self._curve.rawlib.get_x
        with c_uint8_ptr_out(xb) as xb_ptr:
            result = get_x(xb_ptr, c_size_t(modulus_bytes), self._point.get())
        if result == 19:  # ERR_ECC_PAI
            raise ValueError("No X coordinate for the point at infinity")
        if result:
            raise ValueError("Error %d while getting X of an EC point" % result)
        return xb

    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits

    def __imul__(self, scalar: int) -> EccXPoint:
        """Multiply this point by a scalar"""

        scalar_func = self._curve.rawlib.scalar
        if scalar < 0:
            raise ValueError("Scalar multiplication is only defined for non-negative integers")
        sb = _encode_scalar(scalar, self.size_in_bytes())
        sb_ptr, sb_len = c_uint8_ptr_len(sb)
        result = scalar_func(self._point.get(), sb_ptr, c_size_t(sb_len), c_ulonglong(getrandbits(64)))
        if result:
            raise ValueError("Error %d during scalar multiplication" % result)
        return self

    def __mul__(self, scalar: int) -> EccXPoint:
        """Return a new point, the scalar product of this one"""

        np = self.copy()
        np *= scalar
        return np

    def __rmul__(self, left_hand: int) -> EccXPoint:
        return self.__mul__(left_hand)
