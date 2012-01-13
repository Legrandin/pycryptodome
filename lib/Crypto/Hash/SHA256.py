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

# The OID for SHA-256 is:
#
# id-sha256    OBJECT IDENTIFIER ::= {
# 			joint-iso-itu-t(2) country(16) us(840) organization(1)
# 			gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1
# 			}
#
oid = b('\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01')

def new(data=b("")):
    obj = Wrapper(hashFactory, data)
    obj.oid = oid
    obj.new = globals()['new']
    if not hasattr(obj, 'digest_size'):
        obj.digest_size = digest_size
    return obj

try:
    import hashlib
    hashFactory = hashlib.sha256

except ImportError:
    from Crypto.Hash import _SHA256
    hashFactory = _SHA256

digest_size = 32
block_size = 64

