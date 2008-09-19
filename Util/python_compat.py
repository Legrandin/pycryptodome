# -*- coding: utf-8 -*-
#
#  Util/python_compat.py : Compatibility code for old versions of Python
#
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# =======================================================================
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

"""Compatibility code for old versions of Python

Currently, this just defines:
    - True and False
    - object
    - isinstance
"""

__revision__ = "$Id$"
__all__ = []

import sys
import __builtin__

# 'True' and 'False' aren't defined in Python 2.1.  Define them.
try:
    True, False
except NameError:
    (True, False) = (1, 0)
    __all__ += ['True', 'False']

# New-style classes were introduced in Python 2.2.  Defining "object" in Python
# 2.1 lets us use new-style classes in versions of Python that support them,
# while still maintaining backward compatibility with old-style classes
try:
    object
except NameError:
    class object: pass
    __all__ += ['object']

# Starting with Python 2.2, isinstance allows a tuple for the second argument.
# Also, builtins like "tuple", "list", "str", "unicode", "int", and "long"
# became first-class types, rather than functions.  We want to support
# constructs like:
#   isinstance(x, (int, long))
# So we hack it for Python 2.1.
try:
    isinstance(5, (int, long))
except TypeError:
    __all__ += ['isinstance']
    _builtin_type_map = {
        tuple: type(()),
        list: type([]),
        str: type(""),
        unicode: type(u""),
        int: type(0),
        long: type(0L),
    }
    def isinstance(obj, t):
        if not __builtin__.isinstance(t, type(())):
            # t is not a tuple
            return __builtin__.isinstance(obj, _builtin_type_map.get(t, t))
        else:
            # t is a tuple
            for typ in t:
                if __builtin__.isinstance(obj, _builtin_type_map.get(typ, typ)):
                    return True
            return False

# vim:set ts=4 sw=4 sts=4 expandtab:
