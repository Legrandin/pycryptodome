"""Make unit test for mont_mult() in mont.c"""

from common import counter, make_main, split64, inverse

def make_test(a, b, modulus):

    assert(0 <= a < modulus)
    assert(0 <= b < modulus)
    assert(modulus & 1)

    R = 1
    nw = 0
    B = 1<<64
    while modulus >= R:
        R <<= 64
        nw += 1

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
        ds += [0] * (nw - len(ds))

    test_nr = counter.next()
    print ""
    print "void test_%d() {" % test_nr
    print "    const uint64_t a[] = {" + ", ".join(a_m_s) + "};"
    print "    const uint64_t b[] = {" + ", ".join(b_m_s) + "};"
    print "    const uint64_t n[] = {" + ", ".join(modulus_s) + "};"
    print "    const uint64_t expected[] = {" + ", ".join(result_m_s) + "};"
    print "    uint64_t out[%d];" % (nw+1)
    print "    uint64_t scratch[%d];" % (2*nw+1)
    print ""
    print "    memset(out, 0xAA, sizeof out);"
    print "    mont_mult(out, a, b, n, %dUL, scratch, %d);" % (m0, nw)
    print "    assert(memcmp(out, expected, 8*%d) == 0);" % nw
    print "    assert(out[%d] == 0xAAAAAAAAAAAAAAAAUL);" % nw
    print "}"
    print ""


print "#include <assert.h>"
print "#include <string.h>"
print "#include <stdint.h>"
print "#include <stdio.h>"
print ""
print "void mont_mult(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0, uint64_t *t, size_t nw);"

make_test(2, 3, 255)
make_test(2, 240, 255)
make_test(189, 240, 255)
make_test(189, 240, 32984723984723984723847)
make_test(189000000, 7878787878, 32984723984723984723847)
make_test(1890000003439483948394839843434, 78787878780003984834673498384734, 3298472398472398472384798743287438734875384758435834539400000033988787)
make_main()
