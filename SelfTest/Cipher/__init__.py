# -*- coding: utf-8 -*-
#
#  SelfTest/Cipher/__init__.py: Self-test for cipher modules
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

"""Self-test for cipher modules"""

__revision__ = "$Id$"

import unittest

def make_testsuite():
    ts = unittest.TestSuite()
    import test_AES;      ts.addTest(test_AES.make_testsuite())
    import test_ARC2;     ts.addTest(test_ARC2.make_testsuite())
    import test_ARC4;     ts.addTest(test_ARC4.make_testsuite())
    import test_Blowfish; ts.addTest(test_Blowfish.make_testsuite())
    import test_CAST;     ts.addTest(test_CAST.make_testsuite())
    import test_IDEA;     ts.addTest(test_IDEA.make_testsuite())
    import test_RC5;      ts.addTest(test_RC5.make_testsuite())
    return ts

if __name__ == '__main__':
    unittest.main(defaultTest='make_testsuite')

# vim:set ts=4 sw=4 sts=4 expandtab:
