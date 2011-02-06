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

# Just use the SHA module from the Python standard library

__revision__ = "$Id$"

__all__ = ['new', 'digest_size']

from Crypto.Util.wrapper import Wrapper

# The OID for SHA-1 is:
#
# id-sha1    OBJECT IDENTIFIER ::= {
#          iso(1) identified-organization(3) oiw(14) secsig(3)
#          algorithms(2) 26
#      }
oid = '\x06\x05\x2b\x0e\x03\x02\x1a'

def new(data=""):
    obj = Wrapper(hashFactory, data)
    obj.oid = oid
    obj.new = globals()['new']
    return obj

try:
    # The sha module is deprecated in Python 2.6, so use hashlib when possible.
    import hashlib
    hashFactory = hashlib.sha1
    digest_size = new().digest_size

except ImportError:
    import sha
    hashFactory = sha
    if hasattr(sha, 'digestsize'):
        digest_size = sha.digestsize

