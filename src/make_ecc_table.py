#!/usr/bin/python

import argparse

declaration = """\
/* This file was automatically generated, do not edit */
#include "common.h"
extern const unsigned {0}_n_tables;
extern const unsigned {0}_window_size;
extern const unsigned {0}_points_per_table;
extern const uint64_t {0}_tables[{1}][{2}][2][{3}];
"""

definition = """\
/* This file was automatically generated, do not edit */
#include "common.h"
const unsigned {0}_n_tables = {1};
const unsigned {0}_window_size = {2};
const unsigned {0}_points_per_table = {3};
/* {4} */
/* Table size: {5} kbytes */
const uint64_t {0}_tables[{1}][{3}][2][{6}] = {{\
"""

point = """\
  {{ /* Point #{0} */
    {{ {1} }},
    {{ {2} }}
  }}{3}\
"""

parser = argparse.ArgumentParser()
parser.add_argument("curve")
parser.add_argument("window_size", type=int)
parser.add_argument("basename")
args = parser.parse_args()

if args.curve == "p256":
    bits = 256
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    msg = "Affine coordinates in Montgomery form"
elif args.curve == "p384":
    bits = 384
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
    msg = "Affine coordinates in Montgomery form"
elif args.curve == "p521":
    bits = 521
    p = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Gx = 0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    Gy = 0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
    msg = "Affine coordinates in plain form (not Montgomery)"
else:
    raise ValueError("Unsupported curve: " + args.curve)


c_file = open(args.basename + ".c", "w")
h_file = open(args.basename + ".h", "w")

words = (bits + 63) // 64
window_size = args.window_size
points_per_table = 2**window_size
n_tables = (bits + window_size - 1) // window_size
byte_size = n_tables * points_per_table * 2 * (bits // 64) * (64 // 8) // 1024
G = Gx, Gy


def double(X1, Y1):
    if X1 == 0 and Y1 == 0:
        return (0, 0)

    XX = pow(X1, 2, p)
    w = -3 + 3 * XX
    Y1Y1 = pow(Y1, 2, p)
    R = 2 * Y1Y1
    sss = 4 * Y1 * R
    RR = pow(R, 2, p)
    B = pow(X1 + R, 2, p) - XX - RR
    h = pow(w, 2, p) - 2 * B
    X3 = 2 * h * Y1 % p
    Y3 = w * (B - h) - 2 * RR % p
    Z3 = sss

    Z3inv = pow(Z3, p - 2, p)
    x3 = X3 * Z3inv % p
    y3 = Y3 * Z3inv % p
    return (x3, y3)


def add(X1, Y1, X2, Y2):
    if X1 == 0 and Y1 == 0:
        return (X2, Y2)
    if X1 == X2 and Y1 == Y2:
        return double(X1, Y1)
    if X1 == X2 and (Y1 + Y2) % p == 0:
        return (0, 0)

    u = Y2 - Y1
    uu = pow(u, 2, p)
    v = X2 - X1
    vv = pow(v, 2, p)
    vvv = v * vv % p
    R = vv * X1 % p
    A = uu - vvv - 2 * R
    X3 = v * A % p
    Y3 = (u * (R - A) - vvv * Y1) % p
    Z3 = vvv

    Z3inv = pow(Z3, p - 2, p)
    x3 = X3 * Z3inv % p
    y3 = Y3 * Z3inv % p
    return (x3, y3)


def get64(z, words):
    """Return a C string with the number encoded into 64-bit words"""

    # Convert to Montgomery form, but only if it's not P521
    if words != 9:
        R = 2 ** (words * 64)
        x = z * R % p
    else:
        x = z

    result = []
    for _ in range(words):
        masked = x & ((1 << 64) - 1)
        result.append("0x%016XULL" % masked)
        x >>= 64
    return ",".join(result)


# Create table with points 0, G, 2G, 3G, .. (2**window_size-1)G
window = [(0, 0)]
for _ in range(points_per_table - 1):
    new_point = add(*window[-1], *G)
    window.append(new_point)

print(declaration.format(args.curve, n_tables, points_per_table, words), file=h_file)
print(
    definition.format(args.curve, n_tables, window_size, points_per_table, msg, byte_size, words), file=c_file
)

for i in range(n_tables):
    print(" { /* Table #%u */" % i, file=c_file)
    for j, w in enumerate(window):
        endc = "" if (j == points_per_table - 1) else ","
        print(point.format(j, get64(w[0], words), get64(w[1], words), endc), file=c_file)
    endc = "" if (i == n_tables - 1) else ","
    print(" }%s" % endc, file=c_file)

    # Move from G to G*2^{w}
    for _ in range(window_size):
        G = double(*G)

    # Update window
    for j in range(1, points_per_table):
        window[j] = add(*window[j - 1], *G)

print("};", file=c_file)
