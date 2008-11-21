# -*- coding: utf-8 -*-
#
#  SelfTest/__init__.py: Self-test for PyCrypto
#
# =======================================================================
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================
#

"""Self tests

These tests should perform quickly and can ideally be used every time an
application runs.
"""

__revision__ = "$Id$"

import sys
import unittest
import StringIO

class SelfTestError(Exception):
    def __init__(self, message, result):
        Exception.__init__(self, message, result)
        self.message = message
        self.result = result

def run(module=None, verbosity=0, stream=None, tests=None, config=None, **kwargs):
    """Execute self-tests.

    This raises SelfTestError if any test is unsuccessful.

    You may optionally pass in a sub-module of SelfTest if you only want to
    perform some of the tests.  For example, the following would test only the
    hash modules:

        Crypto.SelfTest.run(Crypto.SelfTest.Hash)

    """
    if config is None:
        config = {}
    suite = unittest.TestSuite()
    if module is None:
        if tests is None:
            tests = get_tests(config=config)
        suite.addTests(tests)
    else:
        if tests is None:
            suite.addTests(module.get_tests(config=config))
        else:
            raise ValueError("'module' and 'tests' arguments are mutually exclusive")
    if stream is None:
        kwargs['stream'] = StringIO.StringIO()
    runner = unittest.TextTestRunner(verbosity=verbosity, **kwargs)
    result = runner.run(suite)
    if not result.wasSuccessful():
        if stream is None:
            sys.stderr.write(stream.getvalue())
        raise SelfTestError("Self-test failed", result)
    return result

def get_tests(config={}):
    tests = []
    import Cipher; tests += Cipher.get_tests(config=config)
    import Hash;   tests += Hash.get_tests(config=config)
    import PublicKey; tests += PublicKey.get_tests(config=config)
    import Random; tests += Random.get_tests(config=config)
    import Util;   tests += Util.get_tests(config=config)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
