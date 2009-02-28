
# Just use the MD5 module from the Python standard library

__revision__ = "$Id$"

__all__ = ['new', 'digest_size']

try:
    # The md5 module is deprecated in Python 2.6, so use hashlib when possible.
    import hashlib
    def new(data=""):
        return hashlib.md5(data)
    digest_size = new().digest_size

except ImportError:
    from md5 import *

    import md5
    if hasattr(md5, 'digestsize'):
        digest_size = digestsize
        del digestsize
    del md5

