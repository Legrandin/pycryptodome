"""Make unit test for product() in modexp.c"""


from common import counter, make_main, split64


def make_test(a, b):

    # Turn a[], b[] and the result into arrays of 64-bit words
    result = split64(a*b)
    a = split64(a)
    b = split64(b)

    # Pad the output vector with as many padding zeroes as needed
    # Computation does not depend on zero terms
    for _ in xrange(max(len(b), len(a)) - len(b)):
        b.append("0")
    for _ in xrange(max(len(b), len(a)) - len(a)):
        a.append("0")
    result_len = len(b) + len(a)
    for _ in xrange(result_len - len(result)):
        result.append("0")

    # Fill output buffer with values that must be overwritten
    t = [ "0xCCCCCCCCCCCCCCCCULL" ] * result_len

    print ""
    print "void test_%d() {" % counter.next()
    print "    const uint64_t a[] = {" + ", ".join(a) + "};"
    print "    const uint64_t b[] = {" + ", ".join(b) + "};"
    print "    uint64_t t[] = {" + ", ".join(t) + ", 0xAAAAAAAAAAAAAAAAULL};"
    print "    const uint64_t expected_t[] = {" + ", ".join(result) + "};"
    print ""
    print "    product(t, a, b, %d);" % len(a)
    print "    assert(memcmp(t, expected_t, 8*%d) == 0);" % result_len
    #print '    printf("t[{0}]=0x%016lX\\n", t[{0}]);'.format(result_len)
    print "    assert(t[%d] == 0xAAAAAAAAAAAAAAAAULL);" % result_len
    print "}"
    print ""


print "#include <assert.h>"
print "#include <string.h>"
print "#include <stdint.h>"
print "#include <stdio.h>"
print ""
print "void product(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t words);"

make_test(0, 0)
make_test(1, 0)
make_test(27, 98)
make_test(27832782374324, 78237487324872348723847234)
make_test(0x786BF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
make_test(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

make_main()
