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

from Crypto.Util.py3compat import *

__all__ = ['new', 'block_size', 'digest_size']

def __make_constructor():
    try:
        # The sha module is deprecated in Python 2.6, so use hashlib when possible.
        from hashlib import sha1 as _hash_new
    except ImportError:
        from sha import new as _hash_new

    h = _hash_new()
    if hasattr(h, 'new') and hasattr(h, 'name') and hasattr(h, 'digest_size') and hasattr(h, 'block_size'):
        # The module from stdlib has the API that we need.  Just use it.
        return _hash_new
    else:
        # Wrap the hash object in something that gives us the expected API.
        _copy_sentinel = object()
        class _SHA1(object):
            digest_size = 20
            block_size = 64
            oid = "1.3.14.3.2.26"
            def __init__(self, *args):
                if args and args[0] is _copy_sentinel:
                    self._h = args[1]
                else:
                    self._h = _hash_new(*args)
            def copy(self):
                return _SHA1(_copy_sentinel, self._h.copy())
            def update(self, *args):
                f = self.update = self._h.update
                f(*args)
            def digest(self):
                f = self.digest = self._h.digest
                return f()
            def hexdigest(self):
                f = self.hexdigest = self._h.hexdigest
                return f()
        _SHA1.new = _SHA1
        return _SHA1

new = __make_constructor()
del __make_constructor

# The size of the resulting hash in bytes.
digest_size = new().digest_size

# The internal block size of the hash algorithm in bytes.
block_size = new().block_size
