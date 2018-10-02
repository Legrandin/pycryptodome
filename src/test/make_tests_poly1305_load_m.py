"""Make unit test for poly1305_load_m()"""

import struct

from common import counter, make_main, split64

def make_test(secret):

    assert len(secret) <= 16

    padded = secret + b"\x01" + b"\x00" * (20 - len(secret) - 1)
    split = struct.unpack('<IIIII', padded)
    m_out = [ "0x%08xUL" % x for x in split ]

    print ""
    print "void test_%d() {" % counter.next()
    print "    uint8_t secret[%d] = {" % len(secret),
    print      ",".join([str(ord(x)) for x in secret]) + "};"
    print "    uint32_t m[5] = { 0 };"
    print "    const uint32_t expected_m[5] = {" + ", ".join(m_out) + "};"
    print ""
    print "    poly1305_load_m(m, secret, %d);" % len(secret)
    print "    assert(memcmp(m, expected_m, sizeof(m)) == 0);"
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
print "void poly1305_load_m(uint32_t r[5], const uint8_t data[], size_t len);"

for len_secret in range(16+1):
    make_test(b"\xaa" * len_secret)
make_test(b"\xcc" * 16)
make_test(b"\xff" * 16)
make_test(b"12\x00kjskskjp39027")
make_test(b"\x00")
make_test(b"\x00" * 16)
make_main()
