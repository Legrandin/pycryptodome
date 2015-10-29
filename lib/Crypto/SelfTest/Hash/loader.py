#
# SelfTest/Hash/loader.py: Module to load FIPS test vectors
#
# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

import re
import sys
import binascii

# Fix for Python 3.[12]
if sys.version_info[0] == 3 and sys.version_info[1] <= 2:
    unhexlify = lambda x: binascii.unhexlify(x.encode("latin-1"))
else:
    from binascii import unhexlify

def load_fips_test_module(desc, file_in):
    """Return a list of tuples (desc, digest, messages)"""

    line = file_in.readline()

    line_number = 0
    test_number = 1
    results = []

    expected = "Len"
    bitlength = -1
    test_vector = [ desc ]

    while line:
        line_number += 1
        line = file_in.readline()

        # Skip comments and empty lines
        if line.startswith('#') or not line.strip():
            continue

        # Read bit length
        res = re.match("%s = ([0-9A-F]+)" % expected, line)
        if not res:
            raise ValueError("Incorrect test vector format (line %d)" % line_number)

        if expected == "Len":
            bitlength = int(res.group(1))
            # Next state
            expected = "Msg"
        elif expected == "Msg":
            if bitlength == 0:
                bytedata = ""
            else:
                bytedata = unhexlify(res.group(1))
            test_vector.append(bytedata)
            # Next state
            expected = "(MD|Squeezed)"
        elif expected == "(MD|Squeezed)":
            test_vector.append(res.group(2).lower())
            test_vector.reverse()

            # Ignore data with partial number of bits, since our interface
            # does not support it
            if bitlength % 8 == 0:
                results.append(test_vector)

            # Next state
            expected = "Len"
            test_number += 1
            test_vector = [ desc ]
        else:
            raise ValueError("Unexpected line: " + line)

        # This line is ignored
    return results


def load_tests(subdir, file_name):
    import os.path

    base_dir = os.path.dirname(os.path.abspath(__file__))
    abs_file_name = os.path.join(base_dir, "test_vectors", subdir, file_name)
    return load_fips_test_module("Keccak test", open(abs_file_name))

if __name__ == '__main__':

    if len(sys.argv) != 2:
        sys.stdout.write("Usage: %s nist_test_vector.txt\n" % sys.argv[0])
        sys.exit(1)

    results = load_fips_test_module("Keccak test", open(sys.argv[1]))
    # Rebuild the test vectors file,
    # but keep only messages aligned to the byte
    sys.stdout.write("# File generated with %s from %s\n\n" % (sys.argv[0], sys.argv[1]))
    for digest, message, desc in results:
        sys.stdout.write("Len = %d\n" % (len(message) * 8))
        if len(message) == 0:
            enc_msg = "00"
        else:
            enc_msg = binascii.hexlify(message).upper()
        sys.stdout.write("Msg = %s\n" % enc_msg)
        sys.stdout.write("MD = %s\n\n" % digest.upper())
