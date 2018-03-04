"""Make unit test for addmul128() in multiply_32.c"""

class Count(object):
    def __init__(self):
        self.count = 0

    def next(self):
        self.count += 1
        return self.count
counter = Count()

def split64(long_int):
    """Split long_int into 64-bit words big-endian"""

    assert(long_int >= 0)

    if long_int == 0:
        return [ "0" ]

    result = []
    while long_int:
        result += [ "0x%xULL" % (long_int & (2**64-1)) ]
        long_int >>= 64
    return result

def make_test(t, a, b0, b1):

    if b0 == -1:
        b0 = 0xFFFFFFFF
    if b1 == -1:
        b1 = 0xFFFFFFFF

    # What we expect the function to compute
    result = t + a*(b0 + (b1 << 64))

    # Turn a[] and t[] into arrays of 64-bit words
    a = split64(a)
    t_in = split64(t)
    result = split64(result)

    # Computation does not depend on zero terms
    result_len = max(len(result), 2 + len(a))
   
    # Pad the output vector with as many padding zeroes as needed
    for x in xrange(result_len - len(t_in)):
        t_in.append("0")
    for x in xrange(result_len - len(result)):
        result.append("0")

    print ""
    print "void test_%d() {" % counter.next()
    print "    const uint64_t a[] = {" + ", ".join(a) + "};"
    print "    uint64_t t[] = {" + ", ".join(t_in) + ", 0xAAAAAAAAAAAAAAAAULL};"
    print "    const uint64_t expected_t[] = {" + ", ".join(result) + "};"
    print "    size_t result;"
    print ""
    print "    result = addmul128(t, a, 0x%x, 0x%x, %d);" % (b0, b1, len(a))
    print "    assert(memcmp(t, expected_t, 8*%d) == 0);" % result_len
    print "    assert(t[%d] == 0xAAAAAAAAAAAAAAAAULL);" % result_len
    print "    assert(result == %d);" % result_len
    print "}"
    print ""

def make_main():
    print "int main(void) {"
    for i in xrange(1, counter.next()):
        print "    test_%d();" % i
    print "    return 0;"
    print "}"


print "#include <assert.h>"
print "#include <string.h>"
print "#include <stdint.h>"
print "#include <stdio.h>"
print '#include "multiply.h"'

make_test(0, 0, 0, 0)
make_test(0, 1, 1, 0)
make_test(0, 5, 5, 6)
make_test(0, 0xFFFFFFFFFFFFFFFFFFF, -1, -1)
make_test(0xFFFFFFFFFFFFFFFF, 1, 1, 0)
make_test(32783243204234329232323, 9232922323, 39393938, 7393393)
make_test(32783243204234329232323333333333333783839393,
          92329223233877777777777777777777777838333, 0x1000000, 7393393)
make_test(37893272389423987423987429837498237498237498274982374982734982374982734982743982374,
          30309093333334930430493049304930940394039430303000009090909093434930493094039409340930493094309403940394039403940394039403940390493049304943,
          0x1000000, 7393393)
make_main()
