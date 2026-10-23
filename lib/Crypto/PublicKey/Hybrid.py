# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Hybrid keys: a post-quantum key combined with a traditional one.

Currently, the only supported keys are those of the hybrid KEM X-Wing
(ML-KEM-768 combined with X25519).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, NamedTuple, Optional, Union

from Crypto.Hash import SHA3_256, SHAKE256
from Crypto.Protocol.DH import import_x25519_public_key, key_agreement
from Crypto.PublicKey import ECC, MLKEM
from Crypto.PublicKey.ECC import EccKey
from Crypto.Random import get_random_bytes

__all__ = [
    "ParamSet",
    "MLKEM768_X25519",
    "HybridKey",
    "generate",
]

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]

# Length of the seed of a private key (Nseed = Ndk), and of the shared secret (Nss)
_SEED_LEN = 32
_SS_LEN = 32

# The randomness of an ML-KEM encapsulation (Nrandom)
_MLKEM_COINS_LEN = 32


class ParamSet(Enum):
    """The combinations of a post-quantum and a traditional algorithm.
    The value of each member is the name of the combination.

    Currently, the only member is a hybrid KEM (draft-irtf-cfrg-concrete-hybrid-kems, Section 4)."""

    MLKEM768_X25519 = "MLKEM768-X25519"
    """ML-KEM-768 and X25519 (same as X-Wing)"""


# The members of ParamSet, also at the module level (Hybrid.MLKEM768_X25519)

#: Same as :attr:`ParamSet.MLKEM768_X25519`
MLKEM768_X25519 = ParamSet.MLKEM768_X25519


class _Config(NamedTuple):
    pq: MLKEM.ParamSet
    # The traditional component (a nominal group)
    seed_len: int  # Nseed: the input of RandomScalar
    elem_len: int  # Nelem: the encoding of a point
    label: bytes


# Sections 3.1.2 and 4 of draft-irtf-cfrg-concrete-hybrid-kems
_configs = {
    ParamSet.MLKEM768_X25519: _Config(MLKEM.ML_KEM_768, 32, 32, b"\\.//^\\"),
}


def _check_param_set(param_set: ParamSet) -> _Config:
    if not isinstance(param_set, ParamSet):
        raise TypeError("The parameter set must be a member of Crypto.PublicKey.Hybrid.ParamSet")
    return _configs[param_set]


def _random_scalar(cfg: _Config, seed: bytes) -> EccKey:
    """RandomScalar of the nominal group: return the private ECC key for a seed
    of Nseed bytes."""

    assert len(seed) == cfg.seed_len
    return ECC.construct(curve="Curve25519", seed=seed)


def _import_point(cfg: _Config, encoded: bytes) -> EccKey:
    """Decode a point (Nelem bytes)."""

    if len(encoded) != cfg.elem_len:
        raise ValueError("Incorrect length of the ECDH point")
    return import_x25519_public_key(encoded)


def _element_to_shared_secret(priv: EccKey, pub: EccKey) -> bytes:
    """The shared secret of the nominal group, for Exp(pub, priv)"""

    return key_agreement(static_priv=priv, eph_pub=pub, kdf=bytes)


class HybridKey:
    r"""Class defining a hybrid key (private or public):
    a post-quantum key and a traditional key, combined as defined
    by its parameter set.
    For the hybrid KEMs, an ML-KEM key and an ECDH key,
    as in draft-irtf-cfrg-concrete-hybrid-kems.
    Do not instantiate directly.
    Use :func:`generate` instead.

    :ivar param_set: The combination of algorithms.
    :vartype param_set: :class:`ParamSet`
    """

    def __init__(
        self,
        *,
        param_set: ParamSet,
        seed: Optional[Buffer] = None,
        pk: Optional[Buffer] = None,
    ) -> None:
        """Create a new hybrid key.

        Keywords:
          param_set : ParamSet
            The combination of algorithms.
          seed : bytes
            The seed of the private key (32 bytes for the hybrid KEMs).
          pk : bytes
            The public key.

        At least one of ``seed`` and ``pk`` must be present.
        If both are present, they must match.
        """

        self._cfg = _check_param_set(param_set)
        self.param_set = param_set

        self._seed: Optional[bytes] = None
        self._key_t: EccKey

        if seed is not None:
            seed = bytes(seed)
            if len(seed) != _SEED_LEN:
                raise ValueError("The seed must be %d bytes long" % _SEED_LEN)
            self._seed = seed

            # expandDecapsKeyG (draft-irtf-cfrg-hybrid-kems, Section 5.1.1)
            seed_full = SHAKE256.new(seed).read(64 + self._cfg.seed_len)
            self._key_pq = MLKEM.construct(param_set=self._cfg.pq, seed=seed_full[:64])
            self._key_t = _random_scalar(self._cfg, seed_full[64:])
            self._ek_t = self._key_t.public_key().export_key(format="raw")
            if pk is not None and bytes(pk) != self._pk:
                raise ValueError("The private and the public keys do not match")
        elif pk is not None:
            pk = bytes(pk)
            pk_len = MLKEM._sizes[self._cfg.pq].ek_len + self._cfg.elem_len
            if len(pk) != pk_len:
                raise ValueError("The public key must be %d bytes long" % pk_len)
            ek_pq, self._ek_t = pk[: -self._cfg.elem_len], pk[-self._cfg.elem_len :]
            self._key_pq = MLKEM.construct(param_set=self._cfg.pq, ek=ek_pq)
            try:
                self._key_t = _import_point(self._cfg, self._ek_t)
            except ValueError as ve:
                raise ValueError("Invalid ECDH public key") from ve
        else:
            raise ValueError("At least one of 'seed' and 'pk' must be specified")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HybridKey):
            return False

        if other.has_private() != self.has_private():
            return False

        return other.param_set == self.param_set and other._pk == self._pk

    def __repr__(self) -> str:
        return "HybridKey(param_set=%s, private=%s)" % (self.param_set, self.has_private())

    def __getstate__(self) -> dict[str, Any]:
        # A private key must not end up in a pickle (unencrypted, and executable on load)
        if self.has_private():
            from pickle import PicklingError

            raise PicklingError("A private hybrid key cannot be pickled")
        # The ECC key cannot be pickled: only keep the encoding
        return {"param_set": self.param_set, "pk": self._pk}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__init__(param_set=state["param_set"], pk=state["pk"])  # type: ignore[misc]

    def has_private(self) -> bool:
        """``True`` if this is a private key."""

        return self._seed is not None

    @property
    def _pk(self) -> bytes:
        # The public key: the post-quantum public key, followed by the traditional one.
        # For the hybrid KEMs, it is the encapsulation key: the ML-KEM public key,
        # followed by the ECDH public key.
        return self._key_pq.ek + self._ek_t

    def public_key(self) -> HybridKey:
        """A matching hybrid public key.

        Returns:
            a new :class:`HybridKey` object
        """

        return HybridKey(param_set=self.param_set, pk=self._pk)

    def _combine(self, ss_pq: bytes, ss_t: bytes, ct_t: bytes) -> bytes:
        # C2PRICombiner, with SHA3-256 as KDF
        h = SHA3_256.new(ss_pq + ss_t + ct_t + self._ek_t + self._cfg.label)
        return h.digest()

    def _encaps(self, randomness: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Generate a shared secret and encapsulate it.

        ``randomness`` (random if ``None``) is the input of ``EncapsDerand``:
        32 bytes for ML-KEM, followed by Nseed bytes for the ECDH key.
        Return the 32-byte shared secret and the ciphertext.
        """

        if randomness is None:
            randomness = get_random_bytes(_MLKEM_COINS_LEN + self._cfg.seed_len)
        if len(randomness) != _MLKEM_COINS_LEN + self._cfg.seed_len:
            raise ValueError("The randomness must be %d bytes long" % (_MLKEM_COINS_LEN + self._cfg.seed_len))

        # prepareEncapsG (draft-irtf-cfrg-hybrid-kems, Section 5.1.1)
        ss_pq, ct_pq = self._key_pq._encaps(randomness[:_MLKEM_COINS_LEN])
        eph_key = _random_scalar(self._cfg, randomness[_MLKEM_COINS_LEN:])
        ct_t = eph_key.public_key().export_key(format="raw")
        ss_t = _element_to_shared_secret(eph_key, self._key_t)

        return self._combine(ss_pq, ss_t, ct_t), ct_pq + ct_t

    def _decaps(self, ct: bytes) -> bytes:
        """Decapsulate the shared secret from a ciphertext.

        An invalid ML-KEM ciphertext gives a pseudorandom shared secret
        (implicit rejection), but an invalid ECDH point raises :class:`ValueError`."""

        if self._seed is None:
            raise TypeError("This is not a private hybrid key")

        ct_len = MLKEM._sizes[self._cfg.pq].ct_len + self._cfg.elem_len
        if len(ct) != ct_len:
            raise ValueError("The ciphertext must be %d bytes long" % ct_len)
        ct_pq, ct_t = ct[: -self._cfg.elem_len], ct[-self._cfg.elem_len :]

        # prepareDecapsG (draft-irtf-cfrg-hybrid-kems, Section 5.1.1)
        ss_pq = self._key_pq._decaps(ct_pq)
        try:
            ss_t = _element_to_shared_secret(self._key_t, _import_point(self._cfg, ct_t))
        except ValueError as ve:
            raise ValueError("Invalid ECDH point in the ciphertext") from ve

        return self._combine(ss_pq, ss_t, ct_t)


def generate(*, param_set: ParamSet, randfunc: Optional[RNG] = None) -> HybridKey:
    """Generate a new hybrid private key.

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The combination of algorithms, for instance ``Hybrid.MLKEM768_X25519``.

      randfunc (callable):
        Optional. The RNG to read the seed from (32 bytes for the hybrid KEMs).
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

    Returns:
      :class:`HybridKey` : a new private key
    """

    if randfunc is None:
        randfunc = get_random_bytes
    _check_param_set(param_set)
    return HybridKey(param_set=param_set, seed=randfunc(_SEED_LEN))


def _construct(
    *,
    param_set: ParamSet,
    seed: Optional[Buffer] = None,
    pk: Optional[Buffer] = None,
) -> HybridKey:
    """Build a hybrid key (private or public) from its seed and/or its public key.

    For the hybrid KEMs, the seed is the 32-byte decapsulation key, and the public key
    is the encapsulation key: the ML-KEM public key, followed by the X25519 public key.

    Not public yet: hybrid keys can only be generated and used with HPKE."""

    return HybridKey(param_set=param_set, seed=seed, pk=pk)
