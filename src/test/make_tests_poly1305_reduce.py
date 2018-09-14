"""Make unit test for poly1305_reduce()"""

from common import counter, make_main, split32


def make_test(value):

    result = value % (2**130 - 5)

    h_in = split32(value, 5)
    h_out = split32(result, 5)

    print ""
    print "void test_%d() {" % counter.next()
    print "    uint32_t h[5] = {" + ", ".join(h_in) + "};"
    print "    const uint32_t expected_h[5] = {" + ", ".join(h_out) + "};"
    print ""
    print "    poly1305_reduce(h);"
    print "    assert(memcmp(h, expected_h, sizeof(h)) == 0);"
    print "}"
    print ""


print "#ifdef NDEBUG"
print "#undef NDEBUG"
print "#endif"
print "#include <assert.h>"
print "#include <string.h>"
print "#include <stdint.h>"
print "#include <stdio.h>"
print
print "void poly1305_reduce(uint32_t h[5]);"

make_test(0)
make_test(2**130-5-1)
make_test(2**130-5)
make_test(2**130-5+1)
make_test(2*(2**130-5))
make_test(2*(2**130-5)+9)
# make_test(2*(2**130-5)+10) - Fails, since h[5] takes more than 3 bits
make_main()
