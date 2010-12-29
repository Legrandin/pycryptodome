# -*- coding: utf-8 -*-
#
#  Util/py3compat.py : Compatibility code for handling Py3k / Python 2.x
#
# Written in 2010 by Thorsten Behrens
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

"""Compatibility code for handling string/bytes changes from Python 2.x to Py3k
"""

__revision__ = "$Id$"

import sys

if sys.version_info[0] == 2:
    def b(s):
        return s
    def bchr(s):
        return chr(s)
    def bstr(s):
        return str(s)
    def bord(s):
        return ord(s)
else:
    def b(s):
       return s.encode("latin-1") # utf-8 would cause some side-effects we don't want
    def bchr(s):
        return bytes([s])
    def bstr(s):
        if isinstance(s,str):
            return bytes(s,"latin-1")
        else:
            return bytes(s)
    def bord(s):
        return s

# vim:set ts=4 sw=4 sts=4 expandtab:
