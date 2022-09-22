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
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    msg = "Affine coordinates in Montgomery form"
elif args.curve == "p384":
    bits = 384
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
    Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760aB7
    Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5F
    msg = "Affine coordinates in Montgomery form"
elif args.curve == "p521":
    bits = 521
    p = 0x000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    Gx = 0x000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
    Gy = 0x0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
    msg = "Affine coordinates in plain form (not Montgomery)"
else:
    raise ValueError("Unsupported curve: " + args.curve)


c_file = open(args.basename + ".c", "wt")
h_file = open(args.basename + ".h", "wt")

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
        R = 2**(words * 64)
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
print(definition.format(args.curve, n_tables, window_size, points_per_table, msg,
                    byte_size, words), file=c_file)

for i in range(n_tables):
    print(" { /* Table #%u */" % i, file=c_file)
    for j, w in enumerate(window):
        endc = "" if (j == points_per_table - 1) else ","
        print(point.format(j, get64(w[0], words), get64(w[1], words), endc),
              file=c_file)
    endc = "" if (i == n_tables - 1) else ","
    print(" }%s" % endc, file=c_file)

    # Move from G to G*2^{w}
    for j in range(window_size):
        G = double(*G)

    # Update window
    for j in range(1, points_per_table):
        window[j] = add(*window[j-1], *G)

print("};", file=c_file)
