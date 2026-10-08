# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
Legacy module for PKCS#1 v1.5 signatures.

:undocumented: __package__
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, Protocol

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
