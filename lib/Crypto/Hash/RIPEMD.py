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

#
# See http://homes.esat.kuleuven.be/~bosselae/ripemd160.html#More
#
# id-ripemd160      	OBJECT IDENTIFIER ::= {
# 				iso(1) identified-organization(3) teletrust(36)
# 				algorithm(3) hashAlgorithm(2) ripemd160(1)
# 				}

oid = b("\x06\x05\x2b\x24\x03\x02\x01")

def new(data=b("")):
    obj = Wrapper(hashFactory, data)
    obj.oid = oid
    obj.new = globals()['new']
    if not hasattr(obj, 'digest_size'):
        obj.digest_size = digest_size
    return obj

import Crypto.Hash._RIPEMD160 as _RIPEMD160
hashFactory = _RIPEMD160

digest_size = 20

