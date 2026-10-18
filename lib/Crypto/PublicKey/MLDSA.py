# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""ML-DSA keys (FIPS 204)"""

from __future__ import annotations

import hmac
from typing import Callable, NamedTuple, Optional, Union

from Crypto.Random import get_random_bytes
from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)

__all__ = ["MLDSAKey", "generate", "construct"]

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]

_raw_mldsa_lib = load_pycryptodome_raw_lib(
    "Crypto.PublicKey._mldsa",
    """
    int mldsa_keypair(unsigned level,
                      uint8_t *pk, size_t pk_len,
                      uint8_t *sk, size_t sk_len,
                      const uint8_t *seed, size_t seed_len);
    int mldsa_pk_from_sk(unsigned level,
                         uint8_t *pk, size_t pk_len,
                         const uint8_t *sk, size_t sk_len);
    int mldsa_sign(unsigned level,
                   uint8_t *sig, size_t sig_len,
                   const uint8_t *m, size_t m_len,
                   const uint8_t *pre, size_t pre_len,
                   const uint8_t *rnd, size_t rnd_len,
                   const uint8_t *sk, size_t sk_len,
                   int external_mu);
    int mldsa_verify(unsigned level,
                     const uint8_t *sig, size_t sig_len,
                     const uint8_t *m, size_t m_len,
                     const uint8_t *pre, size_t pre_len,
                     const uint8_t *pk, size_t pk_len,
                     int external_mu);
    """,
)

# Error code returned by the C functions for an invalid private key or signature
_ERR_VALUE = 14

# Length of the seed (xi), of the signing nonce (rnd) and of mu, in bytes
_SEED_LEN = 32
_RND_LEN = 32
_MU_LEN = 64


class _ParamSet(NamedTuple):
    name: str
    level: int
    pk_len: int
    sk_len: int
    sig_len: int


# FIPS 204, Table 2
_param_sets = {
    "ML-DSA-44": _ParamSet("ML-DSA-44", 44, 1312, 2560, 2420),
    "ML-DSA-65": _ParamSet("ML-DSA-65", 65, 1952, 4032, 3309),
    "ML-DSA-87": _ParamSet("ML-DSA-87", 87, 2592, 4896, 4627),
}


def _get_param_set(name: str) -> _ParamSet:
    """The parameter set with the given name, like "ML-DSA-44".
    Case, dashes and underscores do not matter ("mldsa44" is also valid)."""

    if not isinstance(name, str):
        raise TypeError("The parameter set must be a string")
    normalized = name.upper().replace("-", "").replace("_", "")
    for param_set in _param_sets.values():
        if param_set.name.replace("-", "") == normalized:
            return param_set
    raise ValueError("Unsupported ML-DSA parameter set '%s'" % name)


class MLDSAKey:
    r"""Class defining an ML-DSA key (private or public).
    Do not instantiate directly.
    Use :func:`generate` or :func:`construct` instead.

    :ivar param_set: The name of the parameter set:
                     ``'ML-DSA-44'``, ``'ML-DSA-65'`` or ``'ML-DSA-87'``.
    :vartype param_set: string
    """

    def __init__(
        self,
        *,
        param_set: str,
        seed: Optional[Buffer] = None,
        sk: Optional[Buffer] = None,
        pk: Optional[Buffer] = None,
    ) -> None:
        """Create a new ML-DSA key.

        Keywords:
          param_set : string
            The name of the parameter set.
          seed : bytes
            The 32-byte seed of the private key.
          sk : bytes
            The expanded private key.
          pk : bytes
            The public key.

        At least one of ``seed``, ``sk`` and ``pk`` must be present.
        If more than one is present, they must match.
        """

        self._ps = _get_param_set(param_set)
        self.param_set = self._ps.name

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
            self._sk = sk
            self._pk = self._pk_from_sk(sk)
        elif pk is not None:
            pk = bytes(pk)
            if len(pk) != self._ps.pk_len:
                raise ValueError("The public key must be %d bytes long" % self._ps.pk_len)
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
        result = _raw_mldsa_lib.mldsa_keypair(
            self._ps.level,
            pk,
            c_size_t(self._ps.pk_len),
            sk,
            c_size_t(self._ps.sk_len),
            seed_ptr,
            c_size_t(seed_len),
        )
        if result:
            raise ValueError("Error %d while generating an ML-DSA key" % result)
        return get_raw_buffer(pk), get_raw_buffer(sk)

    def _pk_from_sk(self, sk: bytes) -> bytes:
        pk = create_string_buffer(self._ps.pk_len)
        sk_ptr, sk_len = c_uint8_ptr_len(sk)
        result = _raw_mldsa_lib.mldsa_pk_from_sk(
            self._ps.level, pk, c_size_t(self._ps.pk_len), sk_ptr, c_size_t(sk_len)
        )
        if result == _ERR_VALUE:
            raise ValueError("Invalid ML-DSA private key")
        if result:
            raise ValueError("Error %d while importing an ML-DSA private key" % result)
        return get_raw_buffer(pk)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MLDSAKey):
            return False

        if other.has_private() != self.has_private():
            return False

        return other.param_set == self.param_set and other._pk == self._pk

    def __repr__(self) -> str:
        return "MLDSAKey(param_set='%s', private=%s)" % (self.param_set, self.has_private())

    def has_private(self) -> bool:
        """``True`` if this key can be used for making signatures."""

        return self._sk is not None

    @property
    def seed(self) -> bytes:
        """The 32-byte seed of the private key (:math:`\\xi` in FIPS 204).

        Not available if the private key was created from the expanded form only."""

        if not self.has_private():
            raise ValueError("This is not a private ML-DSA key")
        if self._seed is None:
            raise ValueError("The seed of this private key is not known")
        return self._seed

    @property
    def sk(self) -> bytes:
        """The expanded private key, encoded as in FIPS 204 (Algorithm 24)."""

        if self._sk is None:
            raise ValueError("This is not a private ML-DSA key")
        return self._sk

    @property
    def pk(self) -> bytes:
        """The public key, encoded as in FIPS 204 (Algorithm 22)."""

        return self._pk

    def public_key(self) -> MLDSAKey:
        """A matching ML-DSA public key.

        Returns:
            a new :class:`MLDSAKey` object
        """

        return MLDSAKey(param_set=self.param_set, pk=self._pk)

    def _sign(self, msg: Buffer, rnd: Buffer, prefix: Buffer = b"", external_mu: bool = False) -> bytes:
        """ML-DSA.Sign_internal (FIPS 204, Algorithm 7).

        The message M' is the concatenation of ``prefix`` and ``msg``.
        If ``external_mu`` is ``True``, ``msg`` is the 64-byte
        message representative :math:`\\mu` instead, and ``prefix`` is ignored.

        ``rnd`` is the 32-byte nonce (all zeroes for the deterministic variant).
        """

        if self._sk is None:
            raise TypeError("This is not a private ML-DSA key")

        msg_ptr, msg_len = c_uint8_ptr_len(msg)
        prefix_ptr, prefix_len = c_uint8_ptr_len(prefix)
        rnd_ptr, rnd_len = c_uint8_ptr_len(rnd)
        sk_ptr, sk_len = c_uint8_ptr_len(self._sk)

        if rnd_len != _RND_LEN:
            raise ValueError("The nonce rnd must be %d bytes long" % _RND_LEN)
        if external_mu and msg_len != _MU_LEN:
            raise ValueError("The message representative mu must be %d bytes long" % _MU_LEN)

        sig = create_string_buffer(self._ps.sig_len)
        result = _raw_mldsa_lib.mldsa_sign(
            self._ps.level,
            sig,
            c_size_t(self._ps.sig_len),
            msg_ptr,
            c_size_t(msg_len),
            prefix_ptr,
            c_size_t(prefix_len),
            rnd_ptr,
            c_size_t(rnd_len),
            sk_ptr,
            c_size_t(sk_len),
            int(external_mu),
        )
        if result:
            raise ValueError("Error %d while signing with ML-DSA" % result)
        return get_raw_buffer(sig)

    def _verify(
        self, msg: Buffer, signature: Buffer, prefix: Buffer = b"", external_mu: bool = False
    ) -> bool:
        """ML-DSA.Verify_internal (FIPS 204, Algorithm 8).

        The message is as for :meth:`_sign`.

        Return ``True`` if the signature is valid, ``False`` otherwise.
        """

        msg_ptr, msg_len = c_uint8_ptr_len(msg)
        prefix_ptr, prefix_len = c_uint8_ptr_len(prefix)
        sig_ptr, sig_len = c_uint8_ptr_len(signature)
        pk_ptr, pk_len = c_uint8_ptr_len(self._pk)

        if external_mu and msg_len != _MU_LEN:
            raise ValueError("The message representative mu must be %d bytes long" % _MU_LEN)
        if sig_len != self._ps.sig_len:
            return False

        result = _raw_mldsa_lib.mldsa_verify(
            self._ps.level,
            sig_ptr,
            c_size_t(sig_len),
            msg_ptr,
            c_size_t(msg_len),
            prefix_ptr,
            c_size_t(prefix_len),
            pk_ptr,
            c_size_t(pk_len),
            int(external_mu),
        )
        if result == _ERR_VALUE:
            return False
        if result:
            raise ValueError("Error %d while verifying an ML-DSA signature" % result)
        return True


def generate(*, param_set: str, randfunc: Optional[RNG] = None) -> MLDSAKey:
    """Generate a new ML-DSA private key (FIPS 204, Algorithm 1).

    Args:
      param_set (string):
        Mandatory. The name of the parameter set:
        ``'ML-DSA-44'``, ``'ML-DSA-65'`` or ``'ML-DSA-87'``.

      randfunc (callable):
        Optional. The RNG to read the 32-byte seed from.
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

    Returns:
      :class:`MLDSAKey` : a new private key
    """

    if randfunc is None:
        randfunc = get_random_bytes
    _get_param_set(param_set)
    return MLDSAKey(param_set=param_set, seed=randfunc(_SEED_LEN))


def construct(
    *,
    param_set: str,
    seed: Optional[Buffer] = None,
    sk: Optional[Buffer] = None,
    pk: Optional[Buffer] = None,
) -> MLDSAKey:
    """Build an ML-DSA key (private or public) from its components.

    Args:
      param_set (string):
        Mandatory. The name of the parameter set:
        ``'ML-DSA-44'``, ``'ML-DSA-65'`` or ``'ML-DSA-87'``.

      seed (bytes):
        The 32-byte seed of a private key (:math:`\\xi` in FIPS 204).

      sk (bytes):
        The expanded private key, encoded as in FIPS 204 (Algorithm 24).
        Its consistency is checked (but not whether it was generated correctly).

      pk (bytes):
        The public key, encoded as in FIPS 204 (Algorithm 22).

    At least one of ``seed``, ``sk`` and ``pk`` must be present.
    If more than one is present, they must match, otherwise :class:`ValueError` is raised.

    Returns:
      :class:`MLDSAKey` : a new ML-DSA key object
    """

    return MLDSAKey(param_set=param_set, seed=seed, sk=sk, pk=pk)
