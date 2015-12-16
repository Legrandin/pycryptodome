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

from Crypto.Util.py3compat import unhexlify

def load_fips_test_module(desc, file_in):
    """Load and parse NIST test vector file

    Return a list of objects with attributes:
        "desc" : string
        "direction" : string ("ENC" or "DEC")
        "key" : bytes
        "iv" : bytes
        "plaintext" : bytes
        "ciphertext" : bytes
    """

    line_number = 0
    results = []
    direction = "ENC"

    class TestVector(object):
        def __init__(self, description, direction):
            self.desc = description
            self.direction = direction

    test_vector = None

    while True:
        line_number += 1
        line = file_in.readline()
        if not line:
            if test_vector is not None:
                results.append(test_vector)
            break
        line = line.strip()

        # Skip comments and empty lines
        if line.startswith('#') or not line:
            continue

        # Toggle direction
        if line == "[ENCRYPT]":
            direction = "ENC"
            continue
        elif line == "[DECRYPT]":
            direction = "DEC"
            continue

        res = re.match("([A-Za-z0-9]+) = ([0-9A-Fa-f]+)", line)
        if not res:
            raise ValueError("Incorrect test vector format (line %d): %s" % (line_number, line))
        token = res.group(1)
        data = res.group(2)

        if token == "COUNT":
            if test_vector is not None:
                results.append(test_vector)
            test_vector = TestVector("%s(%s)" % (desc, data), direction)
        else:
            setattr(test_vector, token.lower(), unhexlify(data))

        # This line is ignored
    return results


def load_tests(subdir, file_name, description):
    import os.path

    base_dir = os.path.dirname(os.path.abspath(__file__))
    abs_file_name = os.path.join(base_dir, "test_vectors", subdir, file_name)
    return load_fips_test_module("%s test (%s)" % (description, file_name), open(abs_file_name))
