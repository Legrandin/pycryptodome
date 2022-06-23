"""Make unit test for mul_25519() in x25519.c"""

from common import counter, make_main, split64, bin2int
from hashlib import sha256
import struct


def make_test(f, g):

    assert(len(f) == 10)
    assert(len(g) == 10)
    for i in range(10):
        assert(f[i] < 2**27)
        assert(g[i] < 2**27)
    fx = ["0x%08X" % x for x in f]
    gx = ["0x%08X" % x for x in g]
    max26 = hex(2**26 - 1)
    max25 = hex(2**25 - 1)

    modulus = 2**255 - 19
    base = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
    fv = 0
    gv = 0
    for i in range(10):
        fv += f[i] * (2**(base[i]))
        gv += g[i] * (2**(base[i]))

    canonical = (fv * gv) % modulus
    results = [canonical, canonical + modulus]
    if canonical < 38:
        results.append(canonical + modulus * 2)

    # Turn results[] into arrays of 64-bit words
    results_hex = []
    for result in results:
        words = split64(result)
        words = words + ["0"] * (4 - len(words))
        results_hex.append(words)

    print("")
    print("void test_%d() {" % next(counter))
    print("    const uint32_t f[10] = {" + ", ".join(fx) + "};")
    print("    const uint32_t g[10] = {" + ", ".join(gx) + "};")
    print("    uint32_t out[10];")
    print("    uint64_t out64[4];")
    print("    uint64_t exp[%d][4] = {" % len(results))
    print("         { " + ",".join(results_hex[0]) + " },")
    print("         { " + ",".join(results_hex[1]) + " }")
    if len(results_hex) == 3:
        print("         ,{ " + ",".join(results_hex[2]) + " }")
    print("    };")
    print("    unsigned match;")
    print("")
    print("    mul_25519(out, f, g);")
    print("    assert(out[0] <= " + max26 + ");")
    print("    assert(out[1] <= " + max25 + ");")
    print("    assert(out[2] <= " + max26 + ");")
    print("    assert(out[3] <= " + max25 + ");")
    print("    assert(out[4] <= " + max26 + ");")
    print("    assert(out[5] <= " + max25 + ");")
    print("    assert(out[6] <= " + max26 + ");")
    print("    assert(out[7] <= " + max25 + ");")
    print("    assert(out[8] <= " + max26 + ");")
    print("    assert(out[9] <= " + max26 + ");")
    print("    convert_le25p5_to_le64(out64, out);")
    print("    match = 0;")
    print("    match |= !memcmp(exp[0], out64, 32);")
    print("    match |= !memcmp(exp[1], out64, 32);")
    if len(results_hex) == 3:
        print("    match |= !memcmp(exp[2], out64, 32);")
    print("    assert(match);")
    print("}")


def make_limb(seed):
    result = bin2int(sha256(struct.pack(">I", seed)).digest()) & ((2**27)-1)
    return result


print("#include <assert.h>")
print("#include <string.h>")
print("#include <stdint.h>")
print("#include <stdio.h>")
print("void convert_le25p5_to_le64(uint64_t out[4], const uint32_t in[10]);")
print("void mul_25519(uint32_t out[10], const uint32_t f[10], const uint32_t g[10]);")

modulus = [0x3ffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]
modulus_m1 = [0x3ffffec, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]
modulus_m2 = [0x3ffffeb, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]
modulus_m40 = [0x3ffffc5, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]

make_test([0]*10, [0]*10)
make_test([1] + [0]*9, [1] + [0]*9)
make_test([30] + [0]*9, [30] + [0]*9)
make_test([0x7ffffed] + [0]*9, [0x7ffffed] + [0]*9)
make_test(modulus, modulus)
make_test(modulus_m1, modulus_m1)
make_test(modulus_m2, modulus_m2)
make_test(modulus, modulus_m2)
make_test(modulus_m40, modulus_m40)

for x in range(100):
    f = [make_limb(1000*x + y) for y in range(10)]
    g = [make_limb(2000*x + y) for y in range(10)]
    make_test(f, g)

make_main()
