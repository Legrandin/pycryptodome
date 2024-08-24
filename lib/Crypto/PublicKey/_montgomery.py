# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from ._curve import _Curve
from Crypto.Math.Numbers import Integer
from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer,
                                  SmartPointer)


def curve25519_curve():
    p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed  # 2**255 - 19
    order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed

    _curve25519_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._curve25519", """
typedef void Point;

int curve25519_new_point(Point **out,
                         const uint8_t x[32],
                         size_t modsize,
                         const void* context);
int curve25519_clone(Point **P, const Point *Q);
void curve25519_free_point(Point *p);
int curve25519_get_x(uint8_t *xb, size_t modsize, Point *p);
int curve25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve25519_cmp(const Point *ecp1, const Point *ecp2);
""")

    class EcLib(object):
        new_point = _curve25519_lib.curve25519_new_point
        clone = _curve25519_lib.curve25519_clone
        free_point = _curve25519_lib.curve25519_free_point
        get_x = _curve25519_lib.curve25519_get_x
        scalar = _curve25519_lib.curve25519_scalar
        cmp = _curve25519_lib.curve25519_cmp

    curve25519 = _Curve(Integer(p),
                        None,
                        Integer(order),
                        Integer(9),
                        None,
                        None,
                        255,
                        "1.3.101.110",      # RFC8410
                        None,
                        "Curve25519",
                        None,
                        EcLib)
    return curve25519


def curve448_curve():
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff  # 2**448 - 2**224 - 1
    order = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3

    _curve448_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._curve448", """
typedef void Curve448Context;
typedef void Curve448Point;

int curve448_new_context(Curve448Context **pec_ctx);
void curve448_free_context(Curve448Context *ec_ctx);
int curve448_new_point(Curve448Point **out,
                       const uint8_t *x,
                       size_t len,
                       const Curve448Context *ec_ctx);
void curve448_free_point(Curve448Point *p);
int curve448_clone(Curve448Point **P, const Curve448Point *Q);
int curve448_get_x(uint8_t *xb, size_t modsize, const Curve448Point *p);
int curve448_scalar(Curve448Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve448_cmp(const Curve448Point *ecp1, const Curve448Point *ecp2);
""")

    class EcLib(object):
        new_context = _curve448_lib.curve448_new_context
        free_context = _curve448_lib.curve448_free_context
        new_point = _curve448_lib.curve448_new_point
        clone = _curve448_lib.curve448_clone
        free_point = _curve448_lib.curve448_free_point
        get_x = _curve448_lib.curve448_get_x
        scalar = _curve448_lib.curve448_scalar
        cmp = _curve448_lib.curve448_cmp

    curve448_context = VoidPointer()
    result = EcLib.new_context(curve448_context.address_of())
    if result:
        raise ImportError("Error %d initializing Curve448 context" % result)

    curve448 = _Curve(Integer(p),
                      None,
                      Integer(order),
                      Integer(5),
                      None,
                      None,
                      448,
                      "1.3.101.111",      # RFC8410
                      SmartPointer(curve448_context.get(), EcLib.free_context),
                      "Curve448",
                      None,
                      EcLib)
    return curve448
