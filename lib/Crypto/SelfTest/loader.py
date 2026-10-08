# SPDX-FileCopyrightText: 2016 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import binascii
import errno
import json
import os
import re
import warnings
from binascii import unhexlify

try:
    import pycryptodome_test_vectors  # type: ignore

    test_vectors_available = True
except ImportError:
    test_vectors_available = False


def _load_tests(dir_comps, file_in, description, conversions):
    """Load and parse a test vector file

    Return a list of objects, one per group of adjacent
    KV lines or for a single line in the form "[.*]".

    For a group of lines, the object has one attribute per line.
    """

    line_number = 0
    results = []

    class TestVector:
        def __init__(self, description, count):
            self.desc = description
            self.count = count
            self.others = []

    test_vector = None
    count = 0
    new_group = True

    while True:
        line_number += 1
        line = file_in.readline()
        if not line:
            if test_vector is not None:
                results.append(test_vector)
            break
        line = line.strip()

        # Skip comments and empty lines
        if line.startswith("#") or not line:
            new_group = True
            continue

        if line.startswith("["):
            if test_vector is not None:
                results.append(test_vector)
            test_vector = None
            results.append(line)
            continue

        if new_group:
            count += 1
            new_group = False
            if test_vector is not None:
                results.append(test_vector)
            test_vector = TestVector("%s (#%d)" % (description, count), count)

        res = re.match("([A-Za-z0-9]+) = ?(.*)", line)
        if not res:
            test_vector.others += [line]
        else:
            token = res.group(1).lower()
            data = res.group(2).lower()

            conversion = conversions.get(token, None)
            if conversion is None:
                if len(data) % 2 != 0:
                    data = "0" + data
                setattr(test_vector, token, binascii.unhexlify(data))
            else:
                setattr(test_vector, token, conversion(data))

        # This line is ignored
    return results


def load_test_vectors(dir_comps, file_name, description, conversions):
    """Load and parse a test vector file, formatted using the NIST style.

    Args:
        dir_comps (list of strings):
          The path components under the ``pycryptodome_test_vectors`` package.
          For instance ``("Cipher", "AES")``.
        file_name (string):
          The name of the file with the test vectors.
        description (string):
          A description applicable to the test vectors in the file.
        conversions (dictionary):
          The dictionary contains functions.
          Values in the file that have an entry in this dictionary
          will be converted usign the matching function.
          Otherwise, values will be considered as hexadecimal and
          converted to binary.

    Returns:
        A list of test vector objects.

    The file is formatted in the following way:

    - Lines starting with "#" are comments and will be ignored.
    - Each test vector is a sequence of 1 or more adjacent lines, where
      each lines is an assignement.
    - Test vectors are separated by an empty line, a comment, or
      a line starting with "[".

    A test vector object has the following attributes:

    - desc (string): description
    - counter (int): the order of the test vector in the file (from 1)
    - others (list): zero or more lines of the test vector that were not assignments
    - left-hand side of each assignment (lowercase): the value of the
      assignement, either converted or bytes.
    """

    results = None

    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)

        description = "%s test (%s)" % (description, file_name)

        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        full_file_name = os.path.join(os.path.join(init_dir, *dir_comps), file_name)
        with open(full_file_name) as file_in:
            results = _load_tests(dir_comps, file_in, description, conversions)

    except FileNotFoundError:
        warnings.warn("Warning: skipping extended tests for " + description, UserWarning, stacklevel=2)

    return results


def load_test_vectors_wycheproof(dir_comps, file_name, description, root_tag={}, group_tag={}, unit_tag={}):
    result = []
    try:
        if not test_vectors_available:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_name)

        init_dir = os.path.dirname(pycryptodome_test_vectors.__file__)
        full_file_name = os.path.join(os.path.join(init_dir, *dir_comps), file_name)
        with open(full_file_name) as file_in:
            tv_tree = json.load(file_in)

    except FileNotFoundError:
        warnings.warn("Warning: skipping extended tests for " + description, UserWarning, stacklevel=2)
        return result

    class TestVector:
        pass

    # Unique attributes that will be converted from
    # hexadecimal to binary, unless the attribute is
    # listed in the unit_tag dict
    unit_attr_hex = {
        "key",
        "iv",
        "aad",
        "msg",
        "ct",
        "tag",
        "label",
        "ikm",
        "salt",
        "info",
        "okm",
        "sig",
        "public",
        "shared",
    }
    unit_attr_hex -= set(unit_tag.keys())

    common_root = {}
    for k, v in root_tag.items():
        common_root[k] = v(tv_tree)

    for group in tv_tree["testGroups"]:
        common_group = {}
        for k, v in group_tag.items():
            common_group[k] = v(group)

        for test in group["tests"]:
            tv = TestVector()

            for k, v in common_root.items():
                setattr(tv, k, v)
            for k, v in common_group.items():
                setattr(tv, k, v)

            tv.id = test["tcId"]
            tv.comment = test["comment"]
            for attr in unit_attr_hex:
                if attr in test:
                    try:
                        setattr(tv, attr, unhexlify(test[attr]))
                    except binascii.Error:
                        raise ValueError(
                            "Error decoding attribute '%s' (tcId=%s, file %s)" % (attr, tv.id, file_name)
                        )
            tv.filename = file_name

            for k, v in unit_tag.items():
                setattr(tv, k, v(test))

            tv.valid = test["result"] != "invalid"
            tv.warning = test["result"] == "acceptable"
            tv.flags = test.get("flags")

            tv.filename = file_name

            result.append(tv)

    return result


def wycheproof_id(tv):
    """Return the pytest ID of a Wycheproof test vector (e.g. 'aes_gcm-12')"""

    name = tv.filename
    if name.endswith("_test.json"):
        name = name[: -len("_test.json")]
    return "%s-%d" % (name, tv.id)
