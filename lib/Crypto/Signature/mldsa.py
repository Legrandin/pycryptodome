# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""ML-DSA and HashML-DSA signatures (FIPS 204)"""

from __future__ import annotations

from typing import Any, Callable, Optional, Protocol, Union, cast

from Crypto.Hash import SHAKE256
from Crypto.PublicKey.MLDSA import MLDSAKey
from Crypto.Random import get_random_bytes
from Crypto.Util._raw_api import is_buffer
from Crypto.Util.asn1 import DerObjectId

__all__ = ["MLDSASigScheme", "MLDSAMuHash", "new"]

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]

# The length of the nonce rnd (FIPS 204, Algorithm 2)
_RND_LEN = 32

# The maximum length of the context string (FIPS 204, Algorithm 2)
_MAX_CONTEXT_LEN = 255

# The length of the message representative mu (FIPS 204, Algorithm 7)
_MU_LEN = 64

# The hash functions and XOFs that HashML-DSA can use (FIPS 204, Section 5.4.1),
# by OID, with the length of the output of an XOF (None for a hash function)
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


class MLDSAMuHash:
    """The message representative :math:`\\mu` of a message, for a given
    public key and context (FIPS 204, Algorithm 7), computed incrementally.

    Pass it to :meth:`MLDSASigScheme.sign` or :meth:`MLDSASigScheme.verify`
    instead of the message: the signature is the same (*ML-DSA*, not *HashML-DSA*),
    but the message can be processed in pieces, or apart from the private key
    (only the public key is needed).

    Args:
        key (:class:`Crypto.PublicKey.MLDSA.MLDSAKey`):
            The key that signs or verifies (only its public part is used).

    Keyword Args:
        data (bytes):
            The first piece of the message (optional).
            The message can also be passed later with :meth:`update`.

        context (bytes):
            Up to 255 bytes of context, as for :func:`new`.
            If ``None`` (default), the context is empty.
    """

    #: The size of :math:`\\mu` in bytes
    digest_size = _MU_LEN

    def __init__(
        self, key: MLDSAKey, *, data: Optional[Buffer] = None, context: Optional[Buffer] = None
    ) -> None:
        if not isinstance(key, MLDSAKey):
            raise TypeError("MLDSAMuHash can only be used with ML-DSA keys")
        context = _check_context(context) or b""

        self._pk = key.pk
        # mu = H(tr || M', 64) with tr = H(pk, 64) and M' = 0 || |ctx| || ctx || M
        tr = SHAKE256.new(self._pk).read(64)
        self._shake = SHAKE256.new(tr + b"\x00" + bytes([len(context)]) + context)
        if data is not None:
            self.update(data)

    def update(self, data: Buffer) -> MLDSAMuHash:
        """Continue with the next piece of the message.

        Args:
            data (bytes): The next piece of the message.
        """

        if not is_buffer(data):
            raise TypeError("The message must be bytes")
        self._shake.update(data)
        return self

    def copy(self) -> MLDSAMuHash:
        """Return a copy of this object, to compute :math:`\\mu` for messages
        that start with the same data."""

        clone = MLDSAMuHash.__new__(MLDSAMuHash)
        clone._pk = self._pk
        clone._shake = self._shake.copy()
        return clone

    def digest(self) -> bytes:
        """Return the 64-byte message representative :math:`\\mu`
        of the message processed so far.

        The object can still be updated afterwards."""

        return self._shake.copy().read(_MU_LEN)


class MLDSASigScheme:
    """An ML-DSA signature object.
    Do not instantiate directly.
    Use :func:`Crypto.Signature.mldsa.new`.
    """

    def __init__(self, key: MLDSAKey, context: Optional[bytes], deterministic: bool, randfunc: RNG) -> None:
        self._key = key
        # None if no context was given (an empty one for sign() and verify())
        self._context = context
        self._deterministic = deterministic
        self._randfunc = randfunc

    def can_sign(self) -> bool:
        """Return ``True`` if this signature object can be used
        for signing messages."""

        return self._key.has_private()

    def _message(self, msg_or_hash: Union[Buffer, Hash, XOF, MLDSAMuHash]) -> tuple[Buffer, bytes, bool]:
        """Split the message M' to sign or verify into a prefix and the rest
        (FIPS 204, Algorithms 2 to 5), or return mu (and ``True``)."""

        # mu = H(tr || M', 64), computed already
        if isinstance(msg_or_hash, MLDSAMuHash):
            # The context is already part of mu: any context given to new() would be ignored
            if self._context is not None:
                raise ValueError("A context cannot be used with an MLDSAMuHash (it has its own)")
            if msg_or_hash._pk != self._key.pk:
                raise ValueError("The MLDSAMuHash was created for another key")
            return msg_or_hash.digest(), b"", True

        context = self._context or b""
        domain = bytes([len(context)]) + context

        # ML-DSA: M' = 0 || |ctx| || ctx || M
        if is_buffer(msg_or_hash):
            return cast(Buffer, msg_or_hash), b"\x00" + domain, False

        # HashML-DSA: M' = 1 || |ctx| || ctx || OID || PH(M)
        oid = getattr(msg_or_hash, "oid", None)
        if oid not in _PRE_HASHES:
            raise TypeError(
                "'msg_or_hash' must be bytes, an MLDSAMuHash, or a hash object of SHA-2, SHA-3 or SHAKE"
            )
        xof_len = _PRE_HASHES[oid]
        if xof_len is None:
            ph = cast(Hash, msg_or_hash).digest()
        else:
            if getattr(msg_or_hash, "_is_squeezing", False):
                raise ValueError("The output of the XOF has already been read")
            ph = cast(XOF, msg_or_hash).copy().read(xof_len)
        return ph, b"\x01" + domain + DerObjectId(oid).encode(), False

    def _rnd(self) -> bytes:
        """The nonce rnd for a new signature (FIPS 204, Algorithm 2)"""

        if self._deterministic:
            return b"\x00" * _RND_LEN
        rnd = self._randfunc(_RND_LEN)
        if len(rnd) != _RND_LEN:
            raise ValueError("randfunc must return %d bytes" % _RND_LEN)
        return rnd

    def sign(self, msg_or_hash: Union[Buffer, Hash, XOF, MLDSAMuHash]) -> bytes:
        """Compute the ML-DSA signature of a message.

        Args:
          msg_or_hash (bytes, an :class:`MLDSAMuHash` or a hash object):
            One of:

            - the message to sign (``bytes``, for *ML-DSA*);
            - an :class:`MLDSAMuHash` that has processed the message (also for *ML-DSA*,
              with the same signature). The context is the one of the :class:`MLDSAMuHash`,
              so this signature object must be created without one (not even an empty one);
            - a hash object that has processed the message (for *HashML-DSA*),
              of :mod:`Crypto.Hash.SHA224`, :mod:`Crypto.Hash.SHA256`,
              :mod:`Crypto.Hash.SHA384`, :mod:`Crypto.Hash.SHA512` (also truncated),
              :mod:`Crypto.Hash.SHA3_224`, :mod:`Crypto.Hash.SHA3_256`, :mod:`Crypto.Hash.SHA3_384`,
              :mod:`Crypto.Hash.SHA3_512`, :mod:`Crypto.Hash.SHAKE128` or :mod:`Crypto.Hash.SHAKE256`.
              The output of a SHAKE object must not have been read yet.

        Returns:
            The signature as ``bytes``: 2420 bytes for ML-DSA-44, 3309 bytes for ML-DSA-65,
            and 4627 bytes for ML-DSA-87.

        Raises:
            TypeError: if the key is not a private key.
        """

        if not self._key.has_private():
            raise TypeError("Private key is needed to sign")

        msg, prefix, external_mu = self._message(msg_or_hash)
        return self._key._sign(msg, self._rnd(), prefix=prefix, external_mu=external_mu)

    def verify(self, msg_or_hash: Union[Buffer, Hash, XOF, MLDSAMuHash], signature: Buffer) -> None:
        """Check if an ML-DSA signature is authentic.

        Args:
          msg_or_hash (bytes, an :class:`MLDSAMuHash` or a hash object):
            The message that was signed, as for :meth:`sign`.
            A signature of a message (``bytes``) can also be verified
            with an :class:`MLDSAMuHash` of that message, and vice versa.

          signature (``bytes``):
            The signature to verify.

        Raises:
            ValueError: if the signature is not authentic.
        """

        msg, prefix, external_mu = self._message(msg_or_hash)
        if not self._key._verify(msg, signature, prefix=prefix, external_mu=external_mu):
            raise ValueError("The signature is not authentic")


def _check_context(context: Optional[Buffer]) -> Optional[bytes]:
    if context is None:
        return None
    if not is_buffer(context):
        raise TypeError("The context must be bytes")
    context = bytes(context)
    if len(context) > _MAX_CONTEXT_LEN:
        raise ValueError("The context must not be longer than %d bytes" % _MAX_CONTEXT_LEN)
    return context


def new(
    key: MLDSAKey,
    context: Optional[Buffer] = None,
    *,
    deterministic: bool = False,
    randfunc: Optional[RNG] = None,
) -> MLDSASigScheme:
    """Create a signature object :class:`MLDSASigScheme` that
    can perform or verify an ML-DSA signature (FIPS 204).

    Args:
        key (:class:`Crypto.PublicKey.MLDSA.MLDSAKey`):
            The key to use for computing the signature (*private* keys only)
            or for verifying one.

        context (bytes):
            Up to 255 bytes of context, a constant byte string
            to separate different protocols or different applications of the same key.
            If ``None`` (default), :meth:`MLDSASigScheme.sign` and :meth:`MLDSASigScheme.verify`
            use an empty context.
            It must be ``None`` to sign or verify with an :class:`MLDSAMuHash`
            (which has its own context).

    Keyword Args:
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
    """

    if not isinstance(key, MLDSAKey):
        raise TypeError("ML-DSA signatures can only be used with ML-DSA keys")

    context = _check_context(context)

    if deterministic and randfunc is not None:
        raise ValueError("'randfunc' cannot be used for deterministic signatures")
    if randfunc is None:
        randfunc = get_random_bytes

    return MLDSASigScheme(key, context, bool(deterministic), randfunc)
