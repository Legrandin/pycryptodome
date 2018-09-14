"""Make unit test for poly1305_accumulate()"""

import struct
from hashlib import sha1


from common import counter, make_main, split32


def make_test(term1, term2):

    assert term1 < 2**(32*5)
    assert term2 < 2**(32*5)

    t1_split = split32(term1, 5)
    t2_split = split32(term2, 5)
    res_split = split32(term1 + term2, 5)

    print ""
    print "void test_%d() {" % counter.next()
    print "    uint32_t h[5] = {" + ",".join(t1_split) + "};"
    print "    uint32_t m[5] = {" + ",".join(t2_split) + "};"
    print "    uint32_t w[5] = {" + ",".join(res_split) + "};"

    print "    poly1305_accumulate(h, m);"
    print "    assert(0 == memcmp(h, w, sizeof(h)));"
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
print "void poly1305_accumulate(uint32_t h[5], const uint32_t m[5]);"

make_test(0, 0xFFFFFFFFFFFFFFFFFFF)
make_test(0xFFFFFFFFFFFFFFFFFFF, 0)
make_test(2**(32*5)-2, 1)
make_test(1, 2**(32*5)-2)

for i in range(100):
    prng1 = sha1(struct.pack('<II', 0, i)).digest()
    prng2 = sha1(struct.pack('<II', 1, i)).digest()
    term1 = term2 = 0
    for piece in range(5):
        term1 = (term1 << 32) + struct.unpack('<I', prng1[piece*4:(piece+1)*4])[0]
        term2 = (term2 << 32) + struct.unpack('<I', prng2[piece*4:(piece+1)*4])[0]
    if term1 + term2 >= 2**(32*5):
        continue
    make_test(term1, term2)

make_main()
