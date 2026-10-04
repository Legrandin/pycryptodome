# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
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

"""
Legacy module for PKCS#1 v1.5 signatures.

:undocumented: __package__
"""

from __future__ import annotations

from typing import Any, Protocol, TYPE_CHECKING

import types

from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import Hash

if TYPE_CHECKING:
    from Crypto.PublicKey.RSA import RsaKey


class PKCS115_SigScheme(Protocol):
    """Interface of the signature object returned by :func:`new`"""

    def can_sign(self) -> bool: ...
    def sign(self, msg_hash: Hash) -> bytes: ...
    def verify(self, msg_hash: Hash, signature: bytes) -> bool: ...


def _pycrypto_verify(self: Any, hash_object: Hash, signature: bytes) -> bool:
    try:
        self._verify(hash_object, signature)
    except (ValueError, TypeError):
        return False
    return True

def new(rsa_key: RsaKey) -> PKCS115_SigScheme:
    pkcs1: Any = pkcs1_15.new(rsa_key)
    pkcs1._verify = pkcs1.verify
    pkcs1.verify = types.MethodType(_pycrypto_verify, pkcs1)
    return pkcs1

