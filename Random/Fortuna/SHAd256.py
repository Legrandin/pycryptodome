# -*- coding: ascii -*-
#
#  Random/Fortuna/SHAd256.py : SHA_d-256 hash function implementation
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

"""\
SHA_d-256 hash function implementation.

This module should comply with PEP 247.
"""

__revision__ = "$Id$"
__all__ = ['new', 'digest_size']

from Crypto.Util.python_compat import *

from binascii import b2a_hex

from Crypto.Hash import SHA256

assert SHA256.digest_size == 32

class _SHAd256(object):
    """SHA-256, doubled.

    Returns SHA-256(SHA-256(data)).
    """

    digest_size = SHA256.digest_size

    _internal = object()

    def __init__(self, internal_api_check, sha256_hash_obj):
        if internal_api_check is not self._internal:
            raise AssertionError("Do not instantiate this class directly.  Use %s.new()" % (__name__,))
        self._h = sha256_hash_obj

    # PEP 247 "copy" method
    def copy(self):
        """Return a copy of this hashing object"""
        return _SHAd256(SHAd256._internal, self._h.copy())

    # PEP 247 "digest" method
    def digest(self):
        """Return the hash value of this object as a binary string"""
        retval = SHA256.new(self._h.digest()).digest()
        assert len(retval) == 32
        return retval

    # PEP 247 "hexdigest" method
    def hexdigest(self):
        """Return the hash value of this object as a (lowercase) hexadecimal string"""
        retval = b2a_hex(self.digest())
        assert len(retval) == 64
        return retval

    # PEP 247 "update" method
    def update(self, data):
        self._h.update(data)

# PEP 247 module-level "digest_size" variable
digest_size = _SHAd256.digest_size

# PEP 247 module-level "new" function
def new(data=""):
    """Return a new SHAd256 hashing object"""
    return _SHAd256(_SHAd256._internal, SHA256.new(data))

# vim:set ts=4 sw=4 sts=4 expandtab:
