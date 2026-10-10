# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from Crypto.Math.Numbers import Integer
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr,
)
from Crypto.Util.number import long_to_bytes

from ._curve import _Curve
from ._ec_lib import load_ec_lib

_ec_cdecl = """
typedef void EcCurve;
typedef void EcPoint;
int ec_nat_new_curve(EcCurve **out,
                     const uint8_t *p,
                     const uint8_t *b,
                     const uint8_t *order,
                     const uint8_t *gx,
                     const uint8_t *gy,
                     size_t len);
void ec_nat_free_curve(EcCurve *curve);
int ec_nat_new_point(EcPoint **out,
                     const uint8_t *x,
                     const uint8_t *y,
                     size_t len,
                     const EcCurve *curve);
void ec_nat_free_point(EcPoint *p);
int ec_nat_get_xy(uint8_t *x,
                  uint8_t *y,
                  size_t len,
                  const EcPoint *p);
int ec_nat_double(EcPoint *p);
int ec_nat_add(EcPoint *a, const EcPoint *b);
int ec_nat_scalar(EcPoint *p,
                  const uint8_t *k,
                  size_t len,
                  uint64_t seed);
int ec_nat_clone(EcPoint **out, const EcPoint *p);
int ec_nat_cmp(const EcPoint *a, const EcPoint *b);
int ec_nat_neg(EcPoint *p);
"""


_ec_lib, _bmi2_adx = load_ec_lib(_ec_cdecl)


class EcLib:
    new_point = _ec_lib.ec_nat_new_point
    free_point = _ec_lib.ec_nat_free_point
    get_xy = _ec_lib.ec_nat_get_xy
    double = _ec_lib.ec_nat_double
    add = _ec_lib.ec_nat_add
    scalar = _ec_lib.ec_nat_scalar
    clone = _ec_lib.ec_nat_clone
    cmp = _ec_lib.ec_nat_cmp
    neg = _ec_lib.ec_nat_neg


def _new_curve(p, b, order, Gx, Gy, bits, oid, desc, openssh):
    """A NIST curve y^2 = x^3 - 3x + b mod p, with generator (Gx, Gy) of order n"""

    size = (bits + 7) // 8
    curve = VoidPointer()
    result = _ec_lib.ec_nat_new_curve(
        curve.address_of(),
        c_uint8_ptr(long_to_bytes(p, size)),
        c_uint8_ptr(long_to_bytes(b, size)),
        c_uint8_ptr(long_to_bytes(order, size)),
        c_uint8_ptr(long_to_bytes(Gx, size)),
        c_uint8_ptr(long_to_bytes(Gy, size)),
        c_size_t(size),
    )
    if result:
        raise ImportError("Error %d initializing %s context" % (result, desc))

    context = SmartPointer(curve.get(), _ec_lib.ec_nat_free_curve)
    return _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        bits,
        oid,
        context,
        desc,
        openssh,
        EcLib,
    )


def p192_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
    b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
    Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
    Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

    return _new_curve(p, b, order, Gx, Gy, 192, "1.2.840.10045.3.1.1", "NIST P-192", "ecdsa-sha2-nistp192")


def p224_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
    b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
    Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
    Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

    return _new_curve(p, b, order, Gx, Gy, 224, "1.3.132.0.33", "NIST P-224", "ecdsa-sha2-nistp224")


def p256_curve():
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    return _new_curve(p, b, order, Gx, Gy, 256, "1.2.840.10045.3.1.7", "NIST P-256", "ecdsa-sha2-nistp256")


def p384_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    return _new_curve(p, b, order, Gx, Gy, 384, "1.3.132.0.34", "NIST P-384", "ecdsa-sha2-nistp384")


def p521_curve():
    p = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
    order = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    Gx = 0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    Gy = 0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    return _new_curve(p, b, order, Gx, Gy, 521, "1.3.132.0.35", "NIST P-521", "ecdsa-sha2-nistp521")
