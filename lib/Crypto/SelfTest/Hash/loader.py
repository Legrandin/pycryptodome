# -*- coding: utf-8 -*-
#
# SelfTest/Hash/loader.py: Module to load FIPS 202 test vectors
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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
