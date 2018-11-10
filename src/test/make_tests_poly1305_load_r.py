"""Make unit test for poly1305_load_r()"""

import struct

from common import counter, make_main, split64


def make_test(secret):

    assert len(secret) == 16

    clamped = bytearray(secret)
    for idx in 3, 7, 11, 15:
        clamped[idx] &= 15
    for idx in 4, 8, 12:
        clamped[idx] &= 252

    split = struct.unpack('<IIII', bytes(clamped))
    r_out = [ "0x%08xUL" % x for x in split ]
    rr_out = [ "0x%08xUL" % ((x>>2)*5) for x in split ]

    print ""
    print "void test_%d() {" % counter.next()
    print "    uint8_t secret[16] = {" + ",".join([str(ord(x)) for x in secret]) + "};"
    print "    uint32_t r[5] = { 0 };"
    print "    uint32_t rr[5] = { 0 };"
    print "    const uint32_t expected_r[5] = {" + ", ".join(r_out) + "};"
    print "    const uint32_t expected_rr[5] = {" + ", ".join(rr_out) + "};"
    print ""
    print "    poly1305_load_r(r, rr, secret);"
    print "    assert(memcmp(r, expected_r, sizeof(r)) == 0);"
    print "    assert(memcmp(rr, expected_rr, sizeof(rr)) == 0);"
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
print "void poly1305_load_r(uint32_t r[4], uint32_t rr[4], const uint8_t secret[]);"

make_test(b"\xaa" * 16)
make_test(b"\xcc" * 16)
make_test(b"\xff" * 16)
make_test(b"12\x00kjskskjp39027")
make_main()
