
# Just use the SHA module from the Python standard library

__revision__ = "$Id$"

from sha import *
import sha
if hasattr(sha, 'digestsize'):
    digest_size = digestsize
    del digestsize
del sha
