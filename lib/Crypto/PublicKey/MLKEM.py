# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""ML-KEM keys (FIPS 203)"""

from __future__ import annotations

import hmac
from enum import Enum
from typing import Any, Callable, NamedTuple, Optional, Union

from Crypto.Random import get_random_bytes
from Crypto.Util._cpu_features import load_avx2_bmi2_lib
from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

__all__ = [
    "ParamSet",
    "ML_KEM_512",
    "ML_KEM_768",
    "ML_KEM_1024",
    "MLKEMKey",
    "generate",
    "construct",
]

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]

_mlkem_cdecl = """
    int mlkem_keypair(unsigned level,
                      uint8_t *pk, size_t pk_len,
                      uint8_t *sk, size_t sk_len,
                      const uint8_t *seed, size_t seed_len);
    int mlkem_check_pk(unsigned level, const uint8_t *pk, size_t pk_len);
    int mlkem_check_sk(unsigned level, const uint8_t *sk, size_t sk_len);
    int mlkem_encaps(unsigned level,
                     uint8_t *ct, size_t ct_len,
                     uint8_t *ss, size_t ss_len,
                     const uint8_t *pk, size_t pk_len,
                     const uint8_t *coins, size_t coins_len);
    int mlkem_decaps(unsigned level,
                     uint8_t *ss, size_t ss_len,
                     const uint8_t *ct, size_t ct_len,
                     const uint8_t *sk, size_t sk_len);
    """

_raw_mlkem_portable_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._mlkem", _mlkem_cdecl)

# The same code compiled for AVX2 and BMI2, with a faster SHA-3 (4 Keccak states at once)
_raw_mlkem_avx2_bmi2_lib = load_avx2_bmi2_lib("Crypto.PublicKey._mlkem_avx2_bmi2", _mlkem_cdecl)

# The implementation used by all ML-KEM keys
if _raw_mlkem_avx2_bmi2_lib is not None:
    _raw_mlkem_lib = _raw_mlkem_avx2_bmi2_lib
else:
    _raw_mlkem_lib = _raw_mlkem_portable_lib

# Error code returned by the C functions for an invalid key
_ERR_VALUE = 14

# Length of the seed (d || z), of the encapsulation randomness (m)
# and of the shared secret (K), in bytes
_SEED_LEN = 64
_COINS_LEN = 32
_SS_LEN = 32


class ParamSet(Enum):
    """The ML-KEM parameter sets (FIPS 203, Section 8).
    The value of each member is its name in FIPS 203."""

    ML_KEM_512 = "ML-KEM-512"
    """NIST security category 1"""

    ML_KEM_768 = "ML-KEM-768"
    """NIST security category 3"""

    ML_KEM_1024 = "ML-KEM-1024"
    """NIST security category 5"""


# The members of ParamSet, also at the module level (MLKEM.ML_KEM_768)

#: Same as :attr:`ParamSet.ML_KEM_512`
ML_KEM_512 = ParamSet.ML_KEM_512
#: Same as :attr:`ParamSet.ML_KEM_768`
ML_KEM_768 = ParamSet.ML_KEM_768
#: Same as :attr:`ParamSet.ML_KEM_1024`
ML_KEM_1024 = ParamSet.ML_KEM_1024


class _Sizes(NamedTuple):
    level: int
    k: int
    pk_len: int
    sk_len: int
    ct_len: int


# FIPS 203, Tables 2 and 3
_sizes = {
    ParamSet.ML_KEM_512: _Sizes(512, 2, 800, 1632, 768),
    ParamSet.ML_KEM_768: _Sizes(768, 3, 1184, 2400, 1088),
    ParamSet.ML_KEM_1024: _Sizes(1024, 4, 1568, 3168, 1568),
}


def _check_param_set(param_set: ParamSet) -> _Sizes:
    if not isinstance(param_set, ParamSet):
        raise TypeError("The parameter set must be a member of Crypto.PublicKey.MLKEM.ParamSet")
    return _sizes[param_set]


class MLKEMKey:
    r"""Class defining an ML-KEM key (private or public).
    Do not instantiate directly.
    Use :func:`generate` or :func:`construct` instead.

    :ivar param_set: The parameter set.
    :vartype param_set: :class:`ParamSet`
    """

    def __init__(
        self,
        *,
        param_set: ParamSet,
        seed: Optional[Buffer] = None,
        sk: Optional[Buffer] = None,
        pk: Optional[Buffer] = None,
    ) -> None:
        """Create a new ML-KEM key.

        Keywords:
          param_set : ParamSet
            The parameter set.
          seed : bytes
            The 64-byte seed of the private key (d || z).
          sk : bytes
            The expanded private key (decapsulation key).
          pk : bytes
            The public key (encapsulation key).

        At least one of ``seed``, ``sk`` and ``pk`` must be present.
        If more than one is present, they must match.
        """

        self._ps = _check_param_set(param_set)
        self.param_set = param_set

        self._seed: Optional[bytes] = None
        self._sk: Optional[bytes] = None

        if seed is not None:
            seed = bytes(seed)
            if len(seed) != _SEED_LEN:
                raise ValueError("The seed must be %d bytes long" % _SEED_LEN)
            self._seed = seed
            self._pk, self._sk = self._keypair(seed)
            if sk is not None and not hmac.compare_digest(bytes(sk), self._sk):
                raise ValueError("The seed and the expanded private key do not match")
        elif sk is not None:
            sk = bytes(sk)
            if len(sk) != self._ps.sk_len:
                raise ValueError("The expanded private key must be %d bytes long" % self._ps.sk_len)
            self._check(_raw_mlkem_lib.mlkem_check_sk, sk, "private")
            self._sk = sk
            # dk = dk_PKE || ek || H(ek) || z (FIPS 203, Algorithm 16)
            self._pk = sk[384 * self._ps.k : 768 * self._ps.k + 32]
        elif pk is not None:
            pk = bytes(pk)
            if len(pk) != self._ps.pk_len:
                raise ValueError("The public key must be %d bytes long" % self._ps.pk_len)
            self._check(_raw_mlkem_lib.mlkem_check_pk, pk, "public")
            self._pk = pk
            return
        else:
            raise ValueError("At least one of 'seed', 'sk' and 'pk' must be specified")

        if pk is not None and bytes(pk) != self._pk:
            raise ValueError("The private and the public keys do not match")

    def _keypair(self, seed: bytes) -> tuple[bytes, bytes]:
        pk = create_string_buffer(self._ps.pk_len)
        sk = create_string_buffer(self._ps.sk_len)
        seed_ptr, seed_len = c_uint8_ptr_len(seed)
        result = _raw_mlkem_lib.mlkem_keypair(
            self._ps.level,
            pk,
            c_size_t(self._ps.pk_len),
            sk,
            c_size_t(self._ps.sk_len),
            seed_ptr,
            c_size_t(seed_len),
        )
        if result:
            raise ValueError("Error %d while generating an ML-KEM key" % result)
        return get_raw_buffer(pk), get_raw_buffer(sk)

    def _check(self, func: Callable[..., int], key: bytes, kind: str) -> None:
        # The modulus check (public key) or the hash check (private key) of FIPS 203
        key_ptr, key_len = c_uint8_ptr_len(key)
        result = func(self._ps.level, key_ptr, c_size_t(key_len))
        if result == _ERR_VALUE:
            raise ValueError("Invalid ML-KEM %s key" % kind)
        if result:
            raise ValueError("Error %d while checking an ML-KEM %s key" % (result, kind))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MLKEMKey):
            return False

        if other.has_private() != self.has_private():
            return False

        return other.param_set == self.param_set and other._pk == self._pk

    def __repr__(self) -> str:
        return "MLKEMKey(param_set=%s, private=%s)" % (self.param_set, self.has_private())

    def __getstate__(self) -> dict[str, Any]:
        # A private key must not end up in a pickle (unencrypted, and executable on load)
        if self.has_private():
            from pickle import PicklingError

            raise PicklingError("A private ML-KEM key cannot be pickled")
        return self.__dict__.copy()

    def has_private(self) -> bool:
        """``True`` if this key can be used for decapsulation."""

        return self._sk is not None

    @property
    def seed(self) -> bytes:
        """The 64-byte seed of the private key (:math:`d \\| z` in FIPS 203).

        Not available if the private key was created from the expanded form only."""

        if not self.has_private():
            raise ValueError("This is not a private ML-KEM key")
        if self._seed is None:
            raise ValueError("The seed of this private key is not known")
        return self._seed

    @property
    def sk(self) -> bytes:
        """The expanded private key (the decapsulation key *dk* of FIPS 203, Algorithm 16)."""

        if self._sk is None:
            raise ValueError("This is not a private ML-KEM key")
        return self._sk

    @property
    def pk(self) -> bytes:
        """The public key (the encapsulation key *ek* of FIPS 203, Algorithm 16)."""

        return self._pk

    def public_key(self) -> MLKEMKey:
        """A matching ML-KEM public key.

        Returns:
            a new :class:`MLKEMKey` object
        """

        return MLKEMKey(param_set=self.param_set, pk=self._pk)

    def _encaps(self, coins: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Generate a shared secret and encapsulate it (FIPS 203, Algorithm 17).

        ``coins`` is the 32-byte randomness *m* (random if ``None``).
        Return the 32-byte shared secret and the ciphertext.
        """

        if coins is None:
            coins = get_random_bytes(_COINS_LEN)
        if len(coins) != _COINS_LEN:
            raise ValueError("The randomness must be %d bytes long" % _COINS_LEN)

        ct = create_string_buffer(self._ps.ct_len)
        ss = create_string_buffer(_SS_LEN)
        pk_ptr, pk_len = c_uint8_ptr_len(self._pk)
        coins_ptr, coins_len = c_uint8_ptr_len(coins)
        result = _raw_mlkem_lib.mlkem_encaps(
            self._ps.level,
            ct,
            c_size_t(self._ps.ct_len),
            ss,
            c_size_t(_SS_LEN),
            pk_ptr,
            c_size_t(pk_len),
            coins_ptr,
            c_size_t(coins_len),
        )
        if result:
            raise ValueError("Error %d during the ML-KEM encapsulation" % result)
        return get_raw_buffer(ss), get_raw_buffer(ct)

    def _decaps(self, ct: bytes) -> bytes:
        """Decapsulate the shared secret from a ciphertext (FIPS 203, Algorithm 18).

        An invalid ciphertext (of the right length) gives a pseudorandom
        shared secret (implicit rejection)."""

        if self._sk is None:
            raise TypeError("This is not a private ML-KEM key")
        if len(ct) != self._ps.ct_len:
            raise ValueError("The ML-KEM ciphertext must be %d bytes long" % self._ps.ct_len)

        ss = create_string_buffer(_SS_LEN)
        ct_ptr, ct_len = c_uint8_ptr_len(ct)
        sk_ptr, sk_len = c_uint8_ptr_len(self._sk)
        result = _raw_mlkem_lib.mlkem_decaps(
            self._ps.level,
            ss,
            c_size_t(_SS_LEN),
            ct_ptr,
            c_size_t(ct_len),
            sk_ptr,
            c_size_t(sk_len),
        )
        if result:
            raise ValueError("Error %d during the ML-KEM decapsulation" % result)
        return get_raw_buffer(ss)


def generate(*, param_set: ParamSet, randfunc: Optional[RNG] = None) -> MLKEMKey:
    """Generate a new ML-KEM private key (FIPS 203, Algorithm 19).

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``MLKEM.ML_KEM_768``.

      randfunc (callable):
        Optional. The RNG to read the 64-byte seed from.
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

    Returns:
      :class:`MLKEMKey` : a new private key
    """

    if randfunc is None:
        randfunc = get_random_bytes
    _check_param_set(param_set)
    return MLKEMKey(param_set=param_set, seed=randfunc(_SEED_LEN))


def construct(
    *,
    param_set: ParamSet,
    seed: Optional[Buffer] = None,
    sk: Optional[Buffer] = None,
    pk: Optional[Buffer] = None,
) -> MLKEMKey:
    """Build an ML-KEM key (private or public) from its components.

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``MLKEM.ML_KEM_768``.

      seed (bytes):
        The 64-byte seed of a private key: :math:`d \\| z` in FIPS 203
        (the input of ``ML-KEM.KeyGen_internal``, Algorithm 16).

      sk (bytes):
        The expanded private key (the decapsulation key *dk*, FIPS 203).
        It must pass the hash check of FIPS 203 (Section 7.3).

      pk (bytes):
        The public key (the encapsulation key *ek*, FIPS 203).
        It must pass the modulus check of FIPS 203 (Section 7.2).

    At least one of ``seed``, ``sk`` and ``pk`` must be present.
    If more than one is present, they must match, otherwise :class:`ValueError` is raised.

    Returns:
      :class:`MLKEMKey` : a new ML-KEM key object
    """

    return MLKEMKey(param_set=param_set, seed=seed, sk=sk, pk=pk)
