# -*- coding: utf-8 -*-
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

__revision__ = "$Id$"

__all__ = ['new', 'digest_size']

from Crypto.Util.wrapper import Wrapper
from Crypto.Util.py3compat import *

# The OID for MD2 is:
#
# id-md2      OBJECT IDENTIFIER ::= {
# 			iso(1) member-body(2) us(840) rsadsi(113549)
# 			digestAlgorithm(2) 2
# 			}

oid = b('\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02')

def new(data=b("")):
    obj = Wrapper(hashFactory, data)
    obj.oid = oid
    obj.new = globals()['new']
    if not hasattr(obj, 'digest_size'):
        obj.digest_size = digest_size
    return obj

import Crypto.Hash._MD2 as _MD2
hashFactory = _MD2

digest_size = 16

