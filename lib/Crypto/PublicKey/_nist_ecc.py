# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from Crypto.Math.Numbers import Integer
from Crypto.Random.random import getrandbits
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr,
    c_ulonglong,
    load_pycryptodome_raw_lib,
)
from Crypto.Util.number import long_to_bytes

from ._curve import _Curve

_ec_lib = load_pycryptodome_raw_lib(
    "Crypto.PublicKey._ec_ws",
    """
typedef void EcContext;
typedef void EcPoint;
int ec_ws_new_context(EcContext **pec_ctx,
                      const uint8_t *modulus,
                      const uint8_t *b,
                      const uint8_t *order,
                      size_t len,
                      uint64_t seed);
void ec_ws_free_context(EcContext *ec_ctx);
int ec_ws_new_point(EcPoint **pecp,
                    const uint8_t *x,
                    const uint8_t *y,
                    size_t len,
                    const EcContext *ec_ctx);
void ec_ws_free_point(EcPoint *ecp);
int ec_ws_get_xy(uint8_t *x,
                 uint8_t *y,
                 size_t len,
                 const EcPoint *ecp);
int ec_ws_double(EcPoint *p);
int ec_ws_add(EcPoint *ecpa, EcPoint *ecpb);
int ec_ws_scalar(EcPoint *ecp,
                 const uint8_t *k,
                 size_t len,
                 uint64_t seed);
int ec_ws_clone(EcPoint **pecp2, const EcPoint *ecp);
int ec_ws_cmp(const EcPoint *ecp1, const EcPoint *ecp2);
int ec_ws_neg(EcPoint *p);
""",
)


class EcLib:
    new_context = _ec_lib.ec_ws_new_context
    free_context = _ec_lib.ec_ws_free_context
    new_point = _ec_lib.ec_ws_new_point
    free_point = _ec_lib.ec_ws_free_point
    get_xy = _ec_lib.ec_ws_get_xy
    double = _ec_lib.ec_ws_double
    add = _ec_lib.ec_ws_add
    scalar = _ec_lib.ec_ws_scalar
    clone = _ec_lib.ec_ws_clone
    cmp = _ec_lib.ec_ws_cmp
    neg = _ec_lib.ec_ws_neg


def p192_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
    b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
    Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
    Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

    p192_modulus = long_to_bytes(p, 24)
    p192_b = long_to_bytes(b, 24)
    p192_order = long_to_bytes(order, 24)

    ec_p192_context = VoidPointer()
    result = _ec_lib.ec_ws_new_context(
        ec_p192_context.address_of(),
        c_uint8_ptr(p192_modulus),
        c_uint8_ptr(p192_b),
        c_uint8_ptr(p192_order),
        c_size_t(len(p192_modulus)),
        c_ulonglong(getrandbits(64)),
    )
    if result:
        raise ImportError("Error %d initializing P-192 context" % result)

    context = SmartPointer(ec_p192_context.get(), _ec_lib.ec_ws_free_context)
    p192 = _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        192,
        "1.2.840.10045.3.1.1",  # ANSI X9.62 / SEC2
        context,
        "NIST P-192",
        "ecdsa-sha2-nistp192",
        EcLib,
    )
    return p192


def p224_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
    b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
    Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
    Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

    p224_modulus = long_to_bytes(p, 28)
    p224_b = long_to_bytes(b, 28)
    p224_order = long_to_bytes(order, 28)

    ec_p224_context = VoidPointer()
    result = _ec_lib.ec_ws_new_context(
        ec_p224_context.address_of(),
        c_uint8_ptr(p224_modulus),
        c_uint8_ptr(p224_b),
        c_uint8_ptr(p224_order),
        c_size_t(len(p224_modulus)),
        c_ulonglong(getrandbits(64)),
    )
    if result:
        raise ImportError("Error %d initializing P-224 context" % result)

    context = SmartPointer(ec_p224_context.get(), _ec_lib.ec_ws_free_context)
    p224 = _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        224,
        "1.3.132.0.33",  # SEC 2
        context,
        "NIST P-224",
        "ecdsa-sha2-nistp224",
        EcLib,
    )
    return p224


def p256_curve():
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    p256_modulus = long_to_bytes(p, 32)
    p256_b = long_to_bytes(b, 32)
    p256_order = long_to_bytes(order, 32)

    ec_p256_context = VoidPointer()
    result = _ec_lib.ec_ws_new_context(
        ec_p256_context.address_of(),
        c_uint8_ptr(p256_modulus),
        c_uint8_ptr(p256_b),
        c_uint8_ptr(p256_order),
        c_size_t(len(p256_modulus)),
        c_ulonglong(getrandbits(64)),
    )
    if result:
        raise ImportError("Error %d initializing P-256 context" % result)

    context = SmartPointer(ec_p256_context.get(), _ec_lib.ec_ws_free_context)
    p256 = _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        256,
        "1.2.840.10045.3.1.7",  # ANSI X9.62 / SEC2
        context,
        "NIST P-256",
        "ecdsa-sha2-nistp256",
        EcLib,
    )
    return p256


def p384_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    p384_modulus = long_to_bytes(p, 48)
    p384_b = long_to_bytes(b, 48)
    p384_order = long_to_bytes(order, 48)

    ec_p384_context = VoidPointer()
    result = _ec_lib.ec_ws_new_context(
        ec_p384_context.address_of(),
        c_uint8_ptr(p384_modulus),
        c_uint8_ptr(p384_b),
        c_uint8_ptr(p384_order),
        c_size_t(len(p384_modulus)),
        c_ulonglong(getrandbits(64)),
    )
    if result:
        raise ImportError("Error %d initializing P-384 context" % result)

    context = SmartPointer(ec_p384_context.get(), _ec_lib.ec_ws_free_context)
    p384 = _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        384,
        "1.3.132.0.34",  # SEC 2
        context,
        "NIST P-384",
        "ecdsa-sha2-nistp384",
        EcLib,
    )
    return p384


def p521_curve():
    p = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
    order = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    Gx = 0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    Gy = 0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    p521_modulus = long_to_bytes(p, 66)
    p521_b = long_to_bytes(b, 66)
    p521_order = long_to_bytes(order, 66)

    ec_p521_context = VoidPointer()
    result = _ec_lib.ec_ws_new_context(
        ec_p521_context.address_of(),
        c_uint8_ptr(p521_modulus),
        c_uint8_ptr(p521_b),
        c_uint8_ptr(p521_order),
        c_size_t(len(p521_modulus)),
        c_ulonglong(getrandbits(64)),
    )
    if result:
        raise ImportError("Error %d initializing P-521 context" % result)

    context = SmartPointer(ec_p521_context.get(), _ec_lib.ec_ws_free_context)
    p521 = _Curve(
        Integer(p),
        Integer(b),
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        521,
        "1.3.132.0.35",  # SEC 2
        context,
        "NIST P-521",
        "ecdsa-sha2-nistp521",
        EcLib,
    )
    return p521
