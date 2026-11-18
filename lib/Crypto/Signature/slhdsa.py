# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""SLH-DSA and HashSLH-DSA signatures (FIPS 205)"""

# The external functions of FIPS 205: slh_sign (Algorithm 22),
# hash_slh_sign (Algorithm 23), slh_verify (Algorithm 24) and
# hash_slh_verify (Algorithm 25). A number in a comment at the end of a line
# is the line of those algorithms (first the pure ones, then the pre-hash ones).
# The differences with the pseudocode:
#
# - the context string is checked (line 1) by new(), which raises
#   an exception instead of returning an error or False;
# - the message is hashed (PH_M) by the caller, who passes the hash object;
# - M' is not built: it is passed to slh_sign_internal and slh_verify_internal
#   as a prefix and the rest (M or PH_M), so a long message is not copied.
#
# slh_keygen (Algorithm 21) is Crypto.PublicKey.SLHDSA.generate().

from __future__ import annotations

from typing import Any, Optional, Protocol, Union, cast

from Crypto.PublicKey.SLHDSA import SLHDSAKey
from Crypto.Random import get_random_bytes
from Crypto.Util._raw_api import is_buffer
from Crypto.Util._threads import threads_param
from Crypto.Util._typing import RNG, Buffer, Message
from Crypto.Util.asn1 import DerObjectId

__all__ = ["SLHDSASigScheme", "new"]


# The maximum length of the context string (FIPS 205, Algorithms 22 to 25, line 1)
_MAX_CONTEXT_LEN = 255

# The hash functions and XOFs that HashSLH-DSA can use (FIPS 205, Section 10.2.2),
# by OID, with the length of the output of an XOF (None for a hash function).
# Algorithm 23 lists SHA-256, SHA-512, SHAKE128 (256 bits) and SHAKE256 (512 bits),
# and allows other approved hash functions and XOFs (line 21).
_PRE_HASHES: dict[str, Optional[int]] = {
    "2.16.840.1.101.3.4.2.4": None,  # SHA-224
    "2.16.840.1.101.3.4.2.1": None,  # SHA-256
    "2.16.840.1.101.3.4.2.2": None,  # SHA-384
    "2.16.840.1.101.3.4.2.3": None,  # SHA-512
    "2.16.840.1.101.3.4.2.5": None,  # SHA-512/224
    "2.16.840.1.101.3.4.2.6": None,  # SHA-512/256
    "2.16.840.1.101.3.4.2.7": None,  # SHA3-224
    "2.16.840.1.101.3.4.2.8": None,  # SHA3-256
    "2.16.840.1.101.3.4.2.9": None,  # SHA3-384
    "2.16.840.1.101.3.4.2.10": None,  # SHA3-512
    "2.16.840.1.101.3.4.2.11": 32,  # SHAKE128, with 256 bits of output
    "2.16.840.1.101.3.4.2.12": 64,  # SHAKE256, with 512 bits of output
}


class Hash(Protocol):
    oid: str

    def digest(self) -> bytes: ...


class XOF(Protocol):
    oid: str

    def copy(self) -> Any: ...

    def read(self, length: int) -> bytes: ...


class SLHDSASigScheme:
    """An SLH-DSA signature object.
    Do not instantiate directly.
    Use :func:`Crypto.Signature.slhdsa.new`.
    """

    def __init__(
        self, key: SLHDSAKey, context: bytes, deterministic: bool, randfunc: RNG, threads: int
    ) -> None:
        self._key = key
        self._context = context
        self._deterministic = deterministic
        self._randfunc = randfunc
        self._threads = threads

    def can_sign(self) -> bool:
        """Return ``True`` if this signature object can be used
        for signing messages."""

        return self._key.has_private()

    def _m_prime(self, msg_or_hash: Union[Buffer, Hash, XOF]) -> Message:
        """M', the message for slh_sign_internal and slh_verify_internal,
        as two pieces to concatenate: a prefix and the rest (M or PH_M),
        so that a long message M is not copied:
        Algorithm 22 (line 8), 23 (lines 8 to 24), 24 (line 4) or 25 (lines 4 to 20)."""

        ctx = self._context

        # SLH-DSA: M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
        if is_buffer(msg_or_hash):
            M = cast(Buffer, msg_or_hash)
            return (b"\x00" + bytes([len(ctx)]) + ctx, M)  # 8 (22), 4 (24)

        # HashSLH-DSA: PH_M and OID (the switch of Algorithms 23 and 25),
        # where OID is the DER encoding of the OID (tag 06, length, value)
        oid = getattr(msg_or_hash, "oid", None)
        if oid not in _PRE_HASHES:
            raise TypeError("'msg_or_hash' must be bytes, or a hash object of SHA-2, SHA-3 or SHAKE")
        xof_len = _PRE_HASHES[oid]
        if xof_len is None:
            PH_M = cast(Hash, msg_or_hash).digest()
        else:
            if getattr(msg_or_hash, "_is_squeezing", False):
                raise ValueError("The output of the XOF has already been read")
            PH_M = cast(XOF, msg_or_hash).copy().read(xof_len)
        OID = DerObjectId(oid).encode()

        # M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
        return (b"\x01" + bytes([len(ctx)]) + ctx + OID, PH_M)  # 24 (23), 20 (25)

    def _addrnd(self) -> Optional[bytes]:
        """addrnd, the randomness of a new signature (Algorithms 22 and 23, lines 4 to 7),
        or ``None`` for the deterministic variant, which skips those lines"""

        if self._deterministic:
            return None
        n = self._key._params.n
        addrnd = self._randfunc(n)  # 4
        if len(addrnd) != n:  # 5
            raise ValueError("randfunc must return %d bytes" % n)  # 6
        return addrnd

    def sign(self, msg_or_hash: Union[Buffer, Hash, XOF]) -> bytes:
        """Compute the SLH-DSA signature of a message.

        Args:
          msg_or_hash (bytes or a hash object):
            One of:

            - the message to sign (``bytes``, for *SLH-DSA*);
            - a hash object that has processed the message (for *HashSLH-DSA*),
              of :mod:`Crypto.Hash.SHA224`, :mod:`Crypto.Hash.SHA256`,
              :mod:`Crypto.Hash.SHA384`, :mod:`Crypto.Hash.SHA512` (also truncated),
              :mod:`Crypto.Hash.SHA3_224`, :mod:`Crypto.Hash.SHA3_256`, :mod:`Crypto.Hash.SHA3_384`,
              :mod:`Crypto.Hash.SHA3_512`, :mod:`Crypto.Hash.SHAKE128` or :mod:`Crypto.Hash.SHAKE256`.
              The output of a SHAKE object must not have been read yet.

        Returns:
            The signature as ``bytes`` (from 3856 to 49856 bytes, depending on the parameter set).

        Raises:
            TypeError: if the key is not a private key.
        """

        if not self._key.has_private():
            raise TypeError("Private key is needed to sign")

        # Algorithm 22 (slh_sign) or 23 (hash_slh_sign); lines 1 to 3 are in new()
        addrnd = self._addrnd()  # 4 to 7
        M_prime = self._m_prime(msg_or_hash)  # 8 (22), 8 to 24 (23)
        SIG = self._key._sign(M_prime, addrnd, threads=self._threads)  # 9 (22), 25 (23)
        return SIG  # 10 (22), 26 (23)

    def verify(self, msg_or_hash: Union[Buffer, Hash, XOF], signature: Buffer) -> None:
        """Check if an SLH-DSA signature is authentic.

        Args:
          msg_or_hash (bytes or a hash object):
            The message that was signed, as for :meth:`sign`.

          signature (``bytes``):
            The signature to verify.

        Raises:
            ValueError: if the signature is not authentic.
        """

        if not is_buffer(signature):
            raise TypeError("The signature must be bytes")

        # Algorithm 24 (slh_verify) or 25 (hash_slh_verify); lines 1 to 3 are in new()
        M_prime = self._m_prime(msg_or_hash)  # 4 (24), 4 to 20 (25)
        if not self._key._verify(M_prime, signature):  # 5 (24), 21 (25)
            raise ValueError("The signature is not authentic")


def new(
    key: SLHDSAKey,
    *,
    context: Optional[Buffer] = None,
    deterministic: bool = False,
    randfunc: Optional[RNG] = None,
    threads: int = 1,
) -> SLHDSASigScheme:
    """Create a signature object :class:`SLHDSASigScheme` that
    can perform or verify an SLH-DSA signature (FIPS 205).

    Args:
        key (:class:`Crypto.PublicKey.SLHDSA.SLHDSAKey`):
            The key to use for computing the signature (*private* keys only)
            or for verifying one.

    Keyword Args:
        context (bytes):
            Up to 255 bytes of context, a constant byte string
            to separate different protocols or different applications of the same key.
            If ``None`` (default), the context is empty.

        deterministic (boolean):
            If ``False`` (default), the signature is *hedged*: it depends on
            fresh random bytes too (the recommended variant).
            If ``True``, the signature is *deterministic*: it only depends on
            the key, the context and the message.
            Verification is the same in both cases.

        randfunc (callable):
            The RNG for the hedged signatures: a function that returns
            the requested number of random bytes.
            If ``None``, :func:`Crypto.Random.get_random_bytes` is used.
            It cannot be combined with ``deterministic=True``.

        threads (integer):
            The maximum number of threads used to sign
            (default: 1, no extra threads; 0 for all CPU cores).
            The signature does not depend on the number of threads.
            Verification always uses one thread (it is fast).
    """

    if not isinstance(key, SLHDSAKey):
        raise TypeError("SLH-DSA signatures can only be used with SLH-DSA keys")

    if context is None:
        context = b""
    if not is_buffer(context):
        raise TypeError("The context must be bytes")
    context = bytes(context)
    # Algorithms 22 to 25, lines 1 to 3
    if len(context) > _MAX_CONTEXT_LEN:
        raise ValueError("The context must not be longer than %d bytes" % _MAX_CONTEXT_LEN)

    if deterministic and randfunc is not None:
        raise ValueError("'randfunc' cannot be used for deterministic signatures")
    if randfunc is None:
        randfunc = get_random_bytes

    threads = threads_param(threads)

    return SLHDSASigScheme(key, context, bool(deterministic), randfunc, threads)
