"""Make unit test for mont_mult() and mont_mult_generic() in mont.c"""

from common import counter, make_main, split64, inverse, bin2int
from hashlib import sha256
import struct

def make_test(a, b, modulus, use_mont=True):

    assert(0 <= a < modulus)
    assert(0 <= b < modulus)
    assert(modulus & 1)

    R = 1
    nw = 0
    B = 1<<64
    while modulus >= R:
        R <<= 64
        nw += 1

    if not use_mont:
        R = 1

    n0 = modulus & (B-1)
    m0 = -inverse(n0, B) % B
    assert(0 < m0 < B)

    a_m = (a*R) % modulus
    b_m = (b*R) % modulus

    # What we expect the function to compute
    result_m = (a*b*R) % modulus

    # Turn data into arrays of 64-bit words
    a_m_s = split64(a_m)
    b_m_s = split64(b_m)
    modulus_s = split64(modulus)
    result_m_s = split64(result_m)

    # Everything must have nw words
    for ds in (a_m_s, b_m_s, modulus_s, result_m_s):
        ds += ["0"] * (nw - len(ds))

    # Modulus also byte encoded, big endian
    modulus_b = []
    while modulus > 0:
        modulus_b.insert(0, hex(modulus % 256))
        modulus >>= 8

    if use_mont:
        test_nr = counter.next()
        print ""
        print "void test_%d() {" % test_nr
        print "    const uint64_t a[] = {" + ", ".join(a_m_s) + "};"
        print "    const uint64_t b[] = {" + ", ".join(b_m_s) + "};"
        print "    const uint64_t n[] = {" + ", ".join(modulus_s) + "};"
        print "    const uint64_t expected[] = {" + ", ".join(result_m_s) + "};"
        print "    uint64_t out[%d];" % (nw+1)
        print "    uint64_t scratch[%d];" % (5*nw)
        print ""
        print "    memset(out, 0xAA, sizeof out);"
        print "    mont_mult_generic(out, a, b, n, %dUL, scratch, %d);" % (m0, nw)
        print "    assert(memcmp(out, expected, 8*%d) == 0);" % nw
        print "    assert(out[%d] == 0xAAAAAAAAAAAAAAAAUL);" % nw
        print "}"
        print ""

    test_nr = counter.next()
    print ""
    print "void test_%d() {" % test_nr
    print "    const uint64_t a[] = {" + ", ".join(a_m_s) + "};"
    print "    const uint64_t b[] = {" + ", ".join(b_m_s) + "};"
    print "    const uint8_t modulus[] = {" + ", ".join(modulus_b) + "};"
    print "    const uint64_t expected[] = {" + ", ".join(result_m_s) + "};"
    print "    uint64_t out[%d];" % (nw+1)
    print "    MontContext *ctx;"
    print "    int res;"
    print "    uint64_t scratch[%d];" % (5*nw)
    print ""
    print
    print "    res = mont_context_init(&ctx, modulus, sizeof modulus);"
    print "    assert(res == 0);"
    print "    memset(out, 0xAA, sizeof out);"
    print "    res = mont_mult(out, a, b, scratch, ctx);"
    print "    assert(res == 0);"
    print "    assert(out[%d] == 0xAAAAAAAAAAAAAAAAUL);" % nw
    print "    assert(memcmp(out, expected, 8*%d) == 0);" % nw
    print "    mont_context_free(ctx);"
    print "}"
    print ""



print "#include <assert.h>"
print "#include <string.h>"
print "#include <stdint.h>"
print "#include <stdio.h>"
print '#include "mont.h"'
print ""
print "void mont_mult_generic(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw);"

p256 = 115792089210356248762697446949407573530086143415290314195533631308867097853951
p384 = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
p521 = 0x000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

make_test(2, 3, 255)
make_test(2, 240, 255)
make_test(189, 240, 255)
make_test(189, 240, 32984723984723984723847)
make_test(189000000, 7878787878, 32984723984723984723847)
make_test(1890000003439483948394839843434, 78787878780003984834673498384734, 3298472398472398472384798743287438734875384758435834539400000033988787)

for x in range(100):
    modulus_len = x//10 + 5 # 40 bit .. 112 bits
    modulus = bin2int(sha256(b"modulus" + struct.pack(">I", x)).digest()[:-modulus_len]) |  1
    a = bin2int(sha256(b"a" + struct.pack(">I", x)).digest()) % modulus
    b = bin2int(sha256(b"b" + struct.pack(">I", x)).digest()) % modulus
    make_test(a, b, modulus)

for x in range(100):
    a = bin2int(sha256(b"a" + struct.pack(">I", x)).digest()) % p256
    b = bin2int(sha256(b"b" + struct.pack(">I", x)).digest()) % p256
    make_test(a, b, p256)

for x in range(100):
    a = bin2int(sha256(b"a" + struct.pack(">I", x)).digest()) % p384
    b = bin2int(sha256(b"b" + struct.pack(">I", x)).digest()) % p384
    make_test(a, b, p384)

for x in range(100):
    a = bin2int(sha256(b"a" + struct.pack(">I", x)).digest()) % p521
    b = bin2int(sha256(b"b" + struct.pack(">I", x)).digest()) % p521
    make_test(a, b, p521, use_mont=False)

make_main()
