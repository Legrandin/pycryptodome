# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from ._curve import _Curve
from Crypto.Math.Numbers import Integer
from Crypto.Util._raw_api import load_pycryptodome_raw_lib


def curve25519_curve():
    p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed  # 2**255 - 19
    order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed

    _curve25519_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._curve25519", """
typedef void Point;

int curve25519_new_point(Point **out,
                         const uint8_t x[32],
                         size_t modsize);
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
