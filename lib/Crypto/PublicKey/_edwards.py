# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from Crypto.Math.Numbers import Integer
from Crypto.Util._raw_api import SmartPointer, VoidPointer, load_pycryptodome_raw_lib

from ._curve import _Curve


def ed25519_curve():
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED  # 2**255 - 19
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    Gx = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    Gy = 0x6666666666666666666666666666666666666666666666666666666666666658

    _ed25519_lib = load_pycryptodome_raw_lib(
        "Crypto.PublicKey._ed25519",
        """
typedef void Point;
int ed25519_new_point(Point **out,
                      const uint8_t x[32],
                      const uint8_t y[32],
                      size_t modsize,
                      const void *context);
int ed25519_clone(Point **P, const Point *Q);
void ed25519_free_point(Point *p);
int ed25519_cmp(const Point *p1, const Point *p2);
int ed25519_neg(Point *p);
int ed25519_get_xy(uint8_t *xb, uint8_t *yb, size_t modsize, Point *p);
int ed25519_double(Point *p);
int ed25519_add(Point *P1, const Point *P2);
int ed25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
""",
    )

    class EcLib:
        new_point = _ed25519_lib.ed25519_new_point
        clone = _ed25519_lib.ed25519_clone
        free_point = _ed25519_lib.ed25519_free_point
        cmp = _ed25519_lib.ed25519_cmp
        neg = _ed25519_lib.ed25519_neg
        get_xy = _ed25519_lib.ed25519_get_xy
        double = _ed25519_lib.ed25519_double
        add = _ed25519_lib.ed25519_add
        scalar = _ed25519_lib.ed25519_scalar

    ed25519 = _Curve(
        Integer(p),
        None,
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        255,
        "1.3.101.112",  # RFC8410
        None,
        "Ed25519",
        "ssh-ed25519",
        EcLib,
    )
    return ed25519


def ed448_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 2**448 - 2**224 - 1
    order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
    Gx = 0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
    Gy = 0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14

    _ed448_lib = load_pycryptodome_raw_lib(
        "Crypto.PublicKey._ed448",
        """
typedef void EcContext;
typedef void PointEd448;
int ed448_new_context(EcContext **pec_ctx);
void ed448_context(EcContext *ec_ctx);
void ed448_free_context(EcContext *ec_ctx);
int ed448_new_point(PointEd448 **out,
                    const uint8_t x[56],
                    const uint8_t y[56],
                    size_t len,
                    const EcContext *context);
int ed448_clone(PointEd448 **P, const PointEd448 *Q);
void ed448_free_point(PointEd448 *p);
int ed448_cmp(const PointEd448 *p1, const PointEd448 *p2);
int ed448_neg(PointEd448 *p);
int ed448_get_xy(uint8_t *xb, uint8_t *yb, size_t len, const PointEd448 *p);
int ed448_double(PointEd448 *p);
int ed448_add(PointEd448 *P1, const PointEd448 *P2);
int ed448_scalar(PointEd448 *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
""",
    )

    class EcLib:
        new_point = _ed448_lib.ed448_new_point
        clone = _ed448_lib.ed448_clone
        free_point = _ed448_lib.ed448_free_point
        cmp = _ed448_lib.ed448_cmp
        neg = _ed448_lib.ed448_neg
        get_xy = _ed448_lib.ed448_get_xy
        double = _ed448_lib.ed448_double
        add = _ed448_lib.ed448_add
        scalar = _ed448_lib.ed448_scalar

    ed448_context = VoidPointer()
    result = _ed448_lib.ed448_new_context(ed448_context.address_of())
    if result:
        raise ImportError("Error %d initializing Ed448 context" % result)

    context = SmartPointer(ed448_context.get(), _ed448_lib.ed448_free_context)

    ed448 = _Curve(
        Integer(p),
        None,
        Integer(order),
        Integer(Gx),
        Integer(Gy),
        None,
        448,
        "1.3.101.113",  # RFC8410
        context,
        "Ed448",
        None,
        EcLib,
    )
    return ed448
