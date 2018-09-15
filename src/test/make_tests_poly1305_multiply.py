"""Make unit test for poly1305_multiply()"""

import struct
from hashlib import sha1
from binascii import unhexlify

from common import counter, make_main, split32


def make_test(term, secret):

    assert term < 2**(32*5)
    assert len(secret) == 16
   
    # Several bits in the secret must be cleared
    clamped = bytearray(secret)
    for idx in 3, 7, 11, 15:
        clamped[idx] &= 15
    for idx in 4, 8, 12:
        clamped[idx] &= 252
    
    # Turn the secret into an integer r
    r = 0
    for x in clamped[::-1]:
        r = (r * 256) + x

    # Work out what the results (2 or 3) should be
    p = 2**130 - 5
    result = (term * r) % p
    all_results = []
    while result < 2**131:
        all_results.append(split32(result, 5))
        result += p
    n_results = len(all_results)

    # Split the term into 32-bit words
    h_split = split32(term, 5)

    print ""
    print "void test_%d() {" % counter.next()
    print "    uint8_t secret[16] = {" + ",".join([str(ord(x)) for x in secret]) + "};"
    print "    uint32_t r[4], rr[4];"
    print "    uint32_t h[5] = {" + ",".join(h_split) + "};"
    print "    int match;";
    for x in range(n_results):
        y = ",".join(all_results[x])
        print "    uint32_t expected_h_%d[5] = { %s };" % (x+1, y)
    print ""
    print "    poly1305_load_r(r, rr, secret);"
    print "    poly1305_multiply(h, r, rr);"
    print "    match = !0;"
    for x in range(n_results):
        print "    match = match && memcmp(h, expected_h_%d, sizeof(h));" % (x+1)
    print "    assert(match == 0);"
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
print "void poly1305_load_r(uint32_t r[4], uint32_t rr[4], const uint8_t secret[16]);"
print "void poly1305_multiply(uint32_t h[5], const uint32_t r[4], const uint32_t rr[4]);"

p = 2**130 - 5

make_test(0, b"X" * 16)
make_test(78923723423432, b"\x00" * 16)

make_test(1, b"\x01" + b"\x00" * 15)
for x in range(0,129,32):
    make_test(2**x, b"\x01" + b"\x00" * 15)
make_test(1, b"\x00"*12 + b'\x04' + b'\x00'*3)

make_test(p, b"\x01" + b"\x00" * 15)

make_test(2**(32*5)-1, b'\xFF'*16)

for i in range(100):
    prng = sha1(struct.pack('<II', 0, i)).digest()
    h = 0
    for piece in range(5):
        h = (h << 32) + struct.unpack('<I', prng[piece*4:(piece+1)*4])[0]
    secret = sha1(struct.pack('<II', 1, i)).digest()[:16]
    make_test(h, secret)

make_test(2**128, unhexlify("746869032069730030322d0278746500"))

make_main()
