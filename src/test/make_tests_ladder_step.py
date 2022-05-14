"""Make unit test for ladder_step() in x25519.c"""

from common import counter, make_main, split64, bin2int
from hashlib import sha256
import struct


def ref(x2, z2, x3, z3, x1):
    mod = 2**255 - 19

    x4 = (x2**2 - z2**2)**2
    z4 = 4*x2*z2*(x2**2 + 486662*x2*z2 + z2**2)
    x5 = 4*((x2*x3 - z2*z3)**2)
    z5 = 4*((x2*z3 - z2*x3)**2)*x1

    return x4 % mod, z4 % mod, x5 % mod, z5 % mod


def make_test_max():

    v = ["0x%08X" % (2**26-1)] * 10

    modulus = 2**255 - 19
    base = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
    n = 0
    for i in range(10):
        n += (2**26 - 1) * (2**(base[i]))
    n %= modulus
    x2_out, z2_out, x3_out, z3_out = ref(n, n, n, n, n)

    # Output
    words = split64(x2_out)
    x2outx = words + ["0"] * (4 - len(words))
    words = split64(z2_out)
    z2outx = words + ["0"] * (4 - len(words))
    words = split64(x3_out)
    x3outx = words + ["0"] * (4 - len(words))
    words = split64(z3_out)
    z3outx = words + ["0"] * (4 - len(words))

    print("")
    print("void test_%d() {" % next(counter))
    print("    uint32_t x2[10] = { " + ",".join(v) + " };")
    print("    uint32_t z2[10] = { " + ",".join(v) + " };")
    print("    uint32_t x3[10] = { " + ",".join(v) + " };")
    print("    uint32_t z3[10] = { " + ",".join(v) + " };")
    print("    uint32_t xp[10] = { " + ",".join(v) + " };")
    print("    const uint64_t x2_out_ref[4] = {" + ", ".join(x2outx) + "};")
    print("    const uint64_t z2_out_ref[4] = {" + ", ".join(z2outx) + "};")
    print("    const uint64_t x3_out_ref[4] = {" + ", ".join(x3outx) + "};")
    print("    const uint64_t z3_out_ref[4] = {" + ", ".join(z3outx) + "};")
    print("    uint64_t x2_out[4] = { 0 };")
    print("    uint64_t z2_out[4] = { 0 };")
    print("    uint64_t x3_out[4] = { 0 };")
    print("    uint64_t z3_out[4] = { 0 };")

    print("")

    print("    ladder_step(x2, z2, x3, z3, xp);")
    print("    convert_le25p5_to_le64(x2_out, x2);")
    print("    convert_le25p5_to_le64(z2_out, z2);")
    print("    convert_le25p5_to_le64(x3_out, x3);")
    print("    convert_le25p5_to_le64(z3_out, z3);")
    print("    reduce_25519_le64(x2_out);")
    print("    reduce_25519_le64(z2_out);")
    print("    reduce_25519_le64(x3_out);")
    print("    reduce_25519_le64(z3_out);")

    print("")

    print("    assert(0 == memcmp(x2_out, x2_out_ref, sizeof x2_out));")
    print("    assert(0 == memcmp(z2_out, z2_out_ref, sizeof z2_out));")
    print("    assert(0 == memcmp(x3_out, x3_out_ref, sizeof x3_out));")
    print("    assert(0 == memcmp(z3_out, z3_out_ref, sizeof z3_out));")
    print("}")


def make_test(x2, z2, x3, z3, xp):

    x2_out, z2_out, x3_out, z3_out = ref(x2, z2, x3, z3, xp)

    # Input
    words = split64(x2)
    x2x = words + ["0"] * (4 - len(words))
    words = split64(z2)
    z2x = words + ["0"] * (4 - len(words))
    words = split64(x3)
    x3x = words + ["0"] * (4 - len(words))
    words = split64(z3)
    z3x = words + ["0"] * (4 - len(words))
    words = split64(xp)
    xpx = words + ["0"] * (4 - len(words))

    # Output
    words = split64(x2_out)
    x2outx = words + ["0"] * (4 - len(words))
    words = split64(z2_out)
    z2outx = words + ["0"] * (4 - len(words))
    words = split64(x3_out)
    x3outx = words + ["0"] * (4 - len(words))
    words = split64(z3_out)
    z3outx = words + ["0"] * (4 - len(words))

    print("")
    print("void test_%d() {" % next(counter))
    print("    const uint64_t x2_in[4] = {" + ", ".join(x2x) + "};")
    print("    const uint64_t z2_in[4] = {" + ", ".join(z2x) + "};")
    print("    const uint64_t x3_in[4] = {" + ", ".join(x3x) + "};")
    print("    const uint64_t z3_in[4] = {" + ", ".join(z3x) + "};")
    print("    const uint64_t xp_in[4] = {" + ", ".join(xpx) + "};")

    print("    const uint64_t x2_out_ref[4] = {" + ", ".join(x2outx) + "};")
    print("    const uint64_t z2_out_ref[4] = {" + ", ".join(z2outx) + "};")
    print("    const uint64_t x3_out_ref[4] = {" + ", ".join(x3outx) + "};")
    print("    const uint64_t z3_out_ref[4] = {" + ", ".join(z3outx) + "};")

    print("    uint32_t x2[10] = { 0 };")
    print("    uint32_t z2[10] = { 0 };")
    print("    uint32_t x3[10] = { 0 };")
    print("    uint32_t z3[10] = { 0 };")
    print("    uint32_t xp[10] = { 0 };")

    print("    uint64_t x2_out[4] = { 0 };")
    print("    uint64_t z2_out[4] = { 0 };")
    print("    uint64_t x3_out[4] = { 0 };")
    print("    uint64_t z3_out[4] = { 0 };")

    print("")

    print("    convert_le64_to_le25p5(x2, x2_in);")
    print("    convert_le64_to_le25p5(z2, z2_in);")
    print("    convert_le64_to_le25p5(x3, x3_in);")
    print("    convert_le64_to_le25p5(z3, z3_in);")
    print("    convert_le64_to_le25p5(xp, xp_in);")

    print("    ladder_step(x2, z2, x3, z3, xp);")

    print("    convert_le25p5_to_le64(x2_out, x2);")
    print("    convert_le25p5_to_le64(z2_out, z2);")
    print("    convert_le25p5_to_le64(x3_out, x3);")
    print("    convert_le25p5_to_le64(z3_out, z3);")
    print("    reduce_25519_le64(x2_out);")
    print("    reduce_25519_le64(z2_out);")
    print("    reduce_25519_le64(x3_out);")
    print("    reduce_25519_le64(z3_out);")

    print("")
    print("    assert(0 == memcmp(x2_out, x2_out_ref, sizeof x2_out));")
    print("    assert(0 == memcmp(z2_out, z2_out_ref, sizeof z2_out));")
    print("    assert(0 == memcmp(x3_out, x3_out_ref, sizeof x3_out));")
    print("    assert(0 == memcmp(z3_out, z3_out_ref, sizeof z3_out));")
    print("}")


def make_limb(seed):
    result = bin2int(sha256(struct.pack(">I", seed)).digest()) & ((2**255)-1)
    return result


print("#include <assert.h>")
print("#include <string.h>")
print("#include <stdint.h>")
print("#include <stdio.h>")
print("void convert_le25p5_to_le64(uint64_t out[4], const uint32_t in[10]);")
print("void convert_le64_to_le25p5(uint32_t out[10], const uint64_t in[4]);")
print("void reduce_25519_le64(uint64_t x[4]);")
print("void ladder_step(uint32_t x2[10], uint32_t z2[10], uint32_t x3[10], uint32_t z3[10], const uint32_t xp[10]);")

make_test_max()
make_test(0, 0, 0, 0, 0)
make_test(1, 1, 1, 1, 1)
make_test(6000, 10, 1000, 19999, 18888)

for x in range(50):
    x2 = make_limb(1000 + x)
    z2 = make_limb(2000 + x)
    x3 = make_limb(3000 + x)
    z3 = make_limb(4000 + x)
    xp = make_limb(5000 + x)
    make_test(x2, z2, x3, z3, xp)

make_main()
