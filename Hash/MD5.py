
# Just use the MD5 module from the Python standard library

from md5 import *

import md5
if hasattr(md5, 'digestsize'):
    digest_size = digestsize
    del digestsize
del md5

