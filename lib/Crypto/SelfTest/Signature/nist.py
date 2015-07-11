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
import os.path
from binascii import unhexlify

from Crypto.Util.py3compat import tobytes


def open_fips_test_file(dir_name, file_name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    abs_file_name = os.path.join(base_dir, "test_vectors", dir_name, file_name)
    return open(abs_file_name, "rt")


def load_hash_by_name(hash_name):
    return __import__("Crypto.Hash." + hash_name, globals(), locals(), ["new"])


def load_test_vector(file_in, skip_hex_conversion):
    """Load a NIST test vector file.

    A test vector file is ASCII and made up by sections (a la Win INI style).
    Each section contains one of more test vectors separated by empty lines.
    Each test vector is a list of assignements. In most cases, the value
    is a binary string encoded in hexadecimal.

    This function returns a map of sections.
    Each element of the map is an array of test vector maps.

    For instance (skipping hex conversion for a moment), the file:

    [Red]
    A = 8

    B = 9
    [Blue]
    C = 8
    D = 3

    becomes:

    { 'Red' : [ {'A':8}, {'B':9} ],
      'Blue' : [ {'C':8, 'D':3} }

    :Parameters:
      file_in : a file-like object
        The file test vectors are read from.
      skip_hex : list of strings
        The test vectors name that will not converted from hex to binary.
    :Returns:
      A map of sections, which each section a list of test vectors.
      A test vector is a map of assignements.
    """

    def convert(param, value):
        if param in skip_hex_conversion:
            return value
        else:
            try:
                if len(value) % 2:
                    value = "0" + value
                return unhexlify(tobytes(value))
            except TypeError:
                print "Offending text (len = %d): %s" % (len(value), value)
                raise

    sections = {}
    current_vector = current_section = None
    line = '\n'
    while line:
        line = file_in.readline()

        # Skip comments
        if line.startswith('#'):
            continue

        # Start of section
        if line.startswith('['):
            if current_vector:
                current_section.append(current_vector)
            res = re.match("\[(.*)\](\s)*", line)
            if not res:
                raise ValueError("Incorrect section line: %s" % line)
            current_section = sections[res.group(1)] = []
            current_vector = {}
            continue

        # Boundary between test vectors (space)?
        if not line.strip():
            if current_vector:
                current_section.append(current_vector)
                current_vector = {}
            continue

        # Just another entry in the vector set
        if current_vector is None:
            raise ValueError("Detected data before section")
        res = re.match("(.*) = ?(\S+)\s*", line)
        if not res:
            raise ValueError("Incorrect data line: %s" % line)
        current_vector[res.group(1)] = convert(res.group(1), res.group(2))

        # End of loop
    if current_vector:
        current_section.append(current_vector)
    return sections
