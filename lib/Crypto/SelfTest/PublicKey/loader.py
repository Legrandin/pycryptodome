# ===================================================================
#
# Copyright (c) 2016, Legrandin <helderijs@gmail.com>
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

from Crypto.Util._file_system import pycryptodome_filename


def load_test_module(desc, file_in):
    """Load and parse a test vector file

    Return a list of objects with attributes:
        "desc"  : string
        "k"     : integer
        "x"     : integer
        "y"     : integer
        "count" : integer
    """

    line_number = 0
    results = []

    class TestVector(object):
        def __init__(self, description, count):
            self.desc = description
            self.count = count

    test_vector = None
    count = 0

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

        res = re.match("([A-Za-z0-9]+) = ([0-9A-Fa-f]+)", line)
        if not res:
            raise ValueError("Incorrect test vector format (line %d): %s" % (line_number, line))
        token = res.group(1)
        data = res.group(2)

        if token == "k":
            count += 1
            if test_vector is not None:
                results.append(test_vector)
            test_vector = TestVector("%s (#%d)" % (desc, count), count)
            setattr(test_vector, token.lower(), int(data))
        else:
            setattr(test_vector, token.lower(), int(data, 16))

        # This line is ignored
    return results


def load_tests(subdir, file_name, description):
    abs_file_name = pycryptodome_filename(
                        ("Crypto", "SelfTest", "PublicKey", "test_vectors", subdir),
                        file_name)
    return load_test_module("%s test (%s)" % (description, file_name), open(abs_file_name))
