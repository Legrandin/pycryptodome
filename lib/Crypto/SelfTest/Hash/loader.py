#
# SelfTest/Hash/loader.py: Module to load FIPS 202 test vectors
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

from Crypto.Util.py3compat import *

import re
from binascii import unhexlify

def load_fips_test_module(file_in):
    line = file_in.readline()

    line_number = 0
    test_number = 1
    results = []

    expected = "Len"
    bitlength = -1
    test_vector = [ " FIPS 202 test" ]

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
                bytedata = b('')
            else:
                bytedata = unhexlify(tobytes(res.group(1)))
            test_vector.append(tostr(bytedata))
            # Next state
            expected = "MD"
        else:
            test_vector.append(res.group(1).lower())
            test_vector.reverse()

            # Ignore data with partial number of bits, since our interface
            # does not support it
            if bitlength % 8 == 0:
                results.append(test_vector)

            # Next state
            expected = "Len"
            test_number += 1
            test_vector = [ " FIPS 202 test" ]

        # This line is ignored
    return results


def load_tests(file_name):
    import os.path

    base_dir = os.path.dirname(os.path.abspath(__file__))
    abs_file_name = os.path.join(base_dir, "test_vectors", "SHA3", file_name)
    return load_fips_test_module(open(abs_file_name))
