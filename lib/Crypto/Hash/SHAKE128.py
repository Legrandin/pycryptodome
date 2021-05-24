# ===================================================================
#
# Copyright (c) 2015, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

from Crypto.Util._raw_api import c_size_t
from Crypto.Hash.cSHAKE128 import cSHAKE128_XOF


# Reuse implementation from cSHAKE128 and
# change a few parameters.
class SHAKE128_XOF(cSHAKE128_XOF):
    """A SHAKE128 hash object.
    Do not instantiate directly.
    Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string
    """

    # ASN.1 Object ID
    oid = "2.16.840.1.101.3.4.2.11"

    # Parameters
    name = "SHAKE128"
    keccak_capacity = c_size_t(32)

    def __init__(self, data=None):
        super().__init__(data=data)

    def new(self, data=None):
        return type(self)(data=data)


def new(data=None):
    """Return a fresh instance of a SHAKE128 object.

    Args:
       data (bytes/bytearray/memoryview):
        The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`update`.
        Optional.

    :Return: A :class:`SHAKE128_XOF` object
    """

    return SHAKE128_XOF(data=data)
