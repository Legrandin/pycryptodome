# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
Legacy module for PKCS#1 PSS signatures.

:undocumented: __package__
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, Optional, Protocol

from Crypto.Signature import pss
from Crypto.Signature.pss import Hash, MaskFunction, RndFunction

if TYPE_CHECKING:
    from Crypto.PublicKey.RSA import RsaKey


class PSS_SigScheme(Protocol):
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


def new(
    rsa_key: RsaKey,
    mgfunc: Optional[MaskFunction] = None,
    saltLen: Optional[int] = None,
    randfunc: Optional[RndFunction] = None,
) -> PSS_SigScheme:
    pkcs1: Any = pss.new(rsa_key, mask_func=mgfunc, salt_bytes=saltLen, rand_func=randfunc)
    pkcs1._verify = pkcs1.verify
    pkcs1.verify = types.MethodType(_pycrypto_verify, pkcs1)
    return pkcs1
