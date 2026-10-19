# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""ML-DSA keys (FIPS 204)"""

from __future__ import annotations

import hmac
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Literal, NamedTuple, Optional, Union, overload

from Crypto.PublicKey import _create_subject_public_key_info, _extract_subject_public_key_info
from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import tobytes
from Crypto.Util._cpu_features import load_avx2_bmi2_lib
from Crypto.Util._raw_api import (
    c_size_t,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util.asn1 import DerBitString, DerInteger, DerNull, DerObjectId, DerOctetString, DerSequence

if TYPE_CHECKING:
    from Crypto.IO._PBES import ProtParams

__all__ = [
    "ParamSet",
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
    "MLDSAKey",
    "generate",
    "construct",
    "import_key",
]

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]

_mldsa_cdecl = """
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
    """

_raw_mldsa_portable_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._mldsa", _mldsa_cdecl)

# The same code compiled for AVX2 and BMI2, with a faster SHA-3 (4 Keccak states at once)
_raw_mldsa_avx2_bmi2_lib = load_avx2_bmi2_lib("Crypto.PublicKey._mldsa_avx2_bmi2", _mldsa_cdecl)

# The implementation used by all ML-DSA keys
if _raw_mldsa_avx2_bmi2_lib is not None:
    _raw_mldsa_lib = _raw_mldsa_avx2_bmi2_lib
else:
    _raw_mldsa_lib = _raw_mldsa_portable_lib

# Error code returned by the C functions for an invalid private key or signature
_ERR_VALUE = 14

# Length of the seed (xi), of the signing nonce (rnd) and of mu, in bytes
_SEED_LEN = 32
_RND_LEN = 32
_MU_LEN = 64


class ParamSet(Enum):
    """The ML-DSA parameter sets (FIPS 204, Section 4).
    The value of each member is its name in FIPS 204."""

    ML_DSA_44 = "ML-DSA-44"
    """NIST security category 2"""

    ML_DSA_65 = "ML-DSA-65"
    """NIST security category 3"""

    ML_DSA_87 = "ML-DSA-87"
    """NIST security category 5"""


# The members of ParamSet, also at the module level (MLDSA.ML_DSA_65)

#: Same as :attr:`ParamSet.ML_DSA_44`
ML_DSA_44 = ParamSet.ML_DSA_44
#: Same as :attr:`ParamSet.ML_DSA_65`
ML_DSA_65 = ParamSet.ML_DSA_65
#: Same as :attr:`ParamSet.ML_DSA_87`
ML_DSA_87 = ParamSet.ML_DSA_87


class _Sizes(NamedTuple):
    level: int
    pk_len: int
    sk_len: int
    sig_len: int


# FIPS 204, Table 2
_sizes = {
    ParamSet.ML_DSA_44: _Sizes(44, 1312, 2560, 2420),
    ParamSet.ML_DSA_65: _Sizes(65, 1952, 4032, 3309),
    ParamSet.ML_DSA_87: _Sizes(87, 2592, 4896, 4627),
}


# id-ml-dsa-* (RFC 9881, Section 2)
_oids = {
    ParamSet.ML_DSA_44: "2.16.840.1.101.3.4.3.17",
    ParamSet.ML_DSA_65: "2.16.840.1.101.3.4.3.18",
    ParamSet.ML_DSA_87: "2.16.840.1.101.3.4.3.19",
}

# The formats of the private key in a OneAsymmetricKey (RFC 9881, Section 6)


def _check_param_set(param_set: ParamSet) -> _Sizes:
    if not isinstance(param_set, ParamSet):
        raise TypeError("The parameter set must be a member of Crypto.PublicKey.MLDSA.ParamSet")
    return _sizes[param_set]


class MLDSAKey:
    r"""Class defining an ML-DSA key (private or public).
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
        """Create a new ML-DSA key.

        Keywords:
          param_set : ParamSet
            The parameter set.
          seed : bytes
            The 32-byte seed of the private key.
          sk : bytes
            The expanded private key.
          pk : bytes
            The public key.

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
        return "MLDSAKey(param_set=%s, private=%s)" % (self.param_set, self.has_private())

    def __getstate__(self) -> dict[str, Any]:
        # A private key must not end up in a pickle (unencrypted, and executable on load)
        if self.has_private():
            from pickle import PicklingError

            raise PicklingError("A private ML-DSA key cannot be pickled: use export_key()")
        return self.__dict__.copy()

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

    @overload
    def export_key(
        self,
        *,
        format: Literal["DER"] = "DER",
        passphrase: Optional[Union[bytes, str]] = None,
        protection: Optional[str] = None,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> bytes: ...

    @overload
    def export_key(
        self,
        *,
        format: Literal["PEM"],
        passphrase: Optional[Union[bytes, str]] = None,
        protection: Optional[str] = None,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> str: ...

    @overload
    def export_key(
        self,
        *,
        format: str = "DER",
        passphrase: Optional[Union[bytes, str]] = None,
        protection: Optional[str] = None,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> Union[bytes, str]: ...

    def export_key(
        self,
        *,
        format: str = "DER",
        passphrase: Optional[Union[bytes, str]] = None,
        protection: Optional[str] = None,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> Union[bytes, str]:
        """Export this ML-DSA key, as defined in `RFC 9881`_.

        A public key is encoded as an X.509 ``SubjectPublicKeyInfo``.

        A private key is encoded as a `PKCS#8`_ ``OneAsymmetricKey``
        (in the clear, or encrypted if ``passphrase`` is set).
        It contains the 32-byte seed (the format recommended by RFC 9881),
        or the expanded private key if the seed of this key is not known
        (see :attr:`seed`).

        Args:
          format (string):
            - ``'DER'`` (default): binary encoding, as ``bytes``.
            - ``'PEM'``: textual encoding of `RFC 7468`_, as a string,
              with the label ``PUBLIC KEY``, ``PRIVATE KEY`` or
              ``ENCRYPTED PRIVATE KEY``.

          passphrase (bytes or string):
            (*Private keys only*) The passphrase to protect the private key
            with PBES2 (`PKCS#8`_ ``EncryptedPrivateKeyInfo``).

          protection (string):
            (*Private keys only*) The encryption scheme, when ``passphrase`` is set.
            For all possible protection schemes,
            refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
            The default is ``'PBKDF2WithHMAC-SHA256AndAES256-CBC'``.

          prot_params (dict):
            (*Private keys only*) The parameters to derive the encryption key
            from the passphrase, when ``passphrase`` is set.
            For all possible values,
            refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
            The defaults meet the OWASP recommendations (with the default
            ``protection``): there is no need to set them.

          randfunc (callable):
            (*Private keys only*) The RNG for the salt and the IV of the
            encryption. If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

          threads (integer):
            (*Private keys only*)
            The maximum number of threads used to derive the encryption key
            with scrypt (default: 1, no extra threads; 0 for all CPU cores).
            Only useful with a scrypt ``protection`` and a
            ``parallelization`` larger than 1 in ``prot_params``.
            The output does not depend on the number of threads.

        .. warning::
            If you don't provide a passphrase, the private key will be
            exported in the clear!

        Returns:
            ``bytes`` (for ``'DER'``) or a multi-line string (for ``'PEM'``)
            with the encoded key.

        .. _`RFC 9881`: https://www.rfc-editor.org/rfc/rfc9881.html
        .. _`PKCS#8`: https://www.rfc-editor.org/rfc/rfc5958.html
        .. _`RFC 7468`: https://www.rfc-editor.org/rfc/rfc7468.html
        """

        from Crypto.IO import PEM

        if format not in ("DER", "PEM"):
            raise ValueError("Unknown format '%s'" % format)

        der = self._export_der(
            passphrase=passphrase,
            protection=protection,
            prot_params=prot_params,
            randfunc=randfunc,
            threads=threads,
        )
        if format == "DER":
            return der

        # RFC 7468, Sections 10, 11 and 13
        if not self.has_private():
            label = "PUBLIC KEY"
        elif passphrase is not None:
            label = "ENCRYPTED PRIVATE KEY"
        else:
            label = "PRIVATE KEY"
        return PEM.encode(der, label) + "\n"

    def _export_der(
        self,
        *,
        passphrase: Optional[Union[bytes, str]] = None,
        protection: Optional[str] = None,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> bytes:
        from Crypto.IO import PKCS8

        oid = _oids[self.param_set]

        if not self.has_private():
            if (
                passphrase is not None
                or protection is not None
                or prot_params is not None
                or randfunc is not None
                or threads != 1
            ):
                raise ValueError(
                    "The parameters of export_key() for private keys cannot be used with a public key"
                )
            # SubjectPublicKeyInfo, without parameters (RFC 9881, Sections 2 and 4)
            return _create_subject_public_key_info(oid, self._pk, None)

        PKCS8._check_kdf_params(threads=threads)
        if passphrase is not None:
            passphrase = tobytes(passphrase)
            if not passphrase:
                raise ValueError("Empty passphrase")
        elif protection is not None or prot_params is not None:
            raise ValueError("'protection' and 'prot_params' require a passphrase")

        # ML-DSA-PrivateKey ::= CHOICE {
        #   seed [0] OCTET STRING (SIZE (32)),
        #   expandedKey OCTET STRING,
        #   both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
        #
        # We write the seed if we know it, otherwise the expanded key
        if self._seed is not None:
            private_key = DerOctetString(self._seed, implicit=0).encode()
        else:
            assert self._sk is not None
            private_key = DerOctetString(self._sk).encode()

        return PKCS8.wrap(
            private_key,
            oid,
            passphrase,
            protection,
            prot_params,
            key_params=None,
            randfunc=randfunc,
            threads=threads,
        )

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


def generate(*, param_set: ParamSet, randfunc: Optional[RNG] = None) -> MLDSAKey:
    """Generate a new ML-DSA private key (FIPS 204, Algorithm 1).

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``MLDSA.ML_DSA_65``.

      randfunc (callable):
        Optional. The RNG to read the 32-byte seed from.
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

    Returns:
      :class:`MLDSAKey` : a new private key
    """

    if randfunc is None:
        randfunc = get_random_bytes
    _check_param_set(param_set)
    return MLDSAKey(param_set=param_set, seed=randfunc(_SEED_LEN))


def construct(
    *,
    param_set: ParamSet,
    seed: Optional[Buffer] = None,
    sk: Optional[Buffer] = None,
    pk: Optional[Buffer] = None,
) -> MLDSAKey:
    """Build an ML-DSA key (private or public) from its components.

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``MLDSA.ML_DSA_65``.

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


# The PEM labels for a certificate (RFC 7468, Section 5.1)
_CERTIFICATE_LABELS = ("CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE")


def _param_set_from_oid(oid: str) -> ParamSet:
    for param_set, ps_oid in _oids.items():
        if ps_oid == oid:
            return param_set
    raise ValueError("Not an ML-DSA key (OID %s)" % oid)


def _import_subject_public_key_info(encoded: bytes) -> MLDSAKey:
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #   algorithm         AlgorithmIdentifier,
    #   subjectPublicKey  BIT STRING }
    spki = DerSequence().decode(encoded, nr_elements=2, strict=True)
    algo = DerSequence().decode(spki[0], nr_elements=(1, 2), strict=True)
    param_set = _param_set_from_oid(DerObjectId().decode(algo[0], strict=True).value)
    # The parameters must be absent (RFC 9881, Section 2), but we also accept NULL
    if len(algo) != 1 and algo[1] != DerNull().encode():
        raise ValueError("The parameters of an ML-DSA AlgorithmIdentifier must be absent")
    pk = DerBitString().decode(spki[1], strict=True).value
    return MLDSAKey(param_set=param_set, pk=pk)


def _import_der(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> tuple[MLDSAKey, str]:
    """Import a DER-encoded key. Return the key, and the PEM label (RFC 7468)
    for that structure."""

    # Tell the formats apart from the first elements of the outer SEQUENCE:
    #
    #   SubjectPublicKeyInfo    SEQUENCE { SEQUENCE, BIT STRING }
    #   Certificate             SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING }
    #   OneAsymmetricKey        SEQUENCE { INTEGER, ... }
    #   EncryptedPrivateKeyInfo SEQUENCE { SEQUENCE, OCTET STRING }
    types = DerSequence().decode(encoded, nr_elements=(2, 3, 4, 5), strict=True).item_types()

    if types[0] == DerInteger:
        key = _import_pkcs8(encoded, passphrase, max_iteration_count, threads, max_memory)
        return key, "PRIVATE KEY"

    if types == [DerSequence, DerBitString]:
        return _import_subject_public_key_info(encoded), "PUBLIC KEY"

    if types == [DerSequence, DerOctetString]:
        key = _import_pkcs8(encoded, passphrase, max_iteration_count, threads, max_memory)
        return key, "ENCRYPTED PRIVATE KEY"

    if types == [DerSequence, DerSequence, DerBitString]:
        return _import_subject_public_key_info(_extract_subject_public_key_info(encoded)), "CERTIFICATE"

    raise ValueError("Not a DER-encoded ML-DSA key")


def _decode_private_key_choice(private_key: bytes) -> tuple[Optional[bytes], Optional[bytes]]:
    """Decode an ML-DSA-PrivateKey into the seed and the expanded private key
    (either can be ``None``)."""

    try:
        return DerOctetString(implicit=0).decode(private_key, strict=True).payload, None
    except ValueError:
        pass
    try:
        return None, DerOctetString().decode(private_key, strict=True).payload
    except ValueError:
        pass
    try:
        both = DerSequence().decode(private_key, nr_elements=2, strict=True)
        seed = DerOctetString().decode(both[0], strict=True).payload
        sk = DerOctetString().decode(both[1], strict=True).payload
        return seed, sk
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid ML-DSA private key: unknown format")


def _import_pkcs8(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> MLDSAKey:
    from Crypto.IO import PKCS8

    unwrapped = PKCS8.unwrap(encoded, passphrase, max_iteration_count, threads=threads, max_memory=max_memory)
    oid, private_key, pk = unwrapped.oid, unwrapped.private_key, unwrapped.public_key
    param_set = _param_set_from_oid(oid)
    # The parameters must be absent (RFC 9881, Section 2), but NULL is accepted too
    if unwrapped.params is not None:
        raise ValueError("The parameters of an ML-DSA AlgorithmIdentifier must be absent")
    sk_len = _sizes[param_set].sk_len

    # ML-DSA-PrivateKey ::= CHOICE {
    #   seed [0] OCTET STRING (SIZE (32)),
    #   expandedKey OCTET STRING,
    #   both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
    #
    # The tag selects the alternative (RFC 9881, Section 6)
    seed, sk = _decode_private_key_choice(private_key)

    if seed is not None and len(seed) != _SEED_LEN:
        raise ValueError("Invalid ML-DSA private key: the seed must be %d bytes long" % _SEED_LEN)
    if sk is not None and len(sk) != sk_len:
        raise ValueError("Invalid ML-DSA private key: the expanded key must be %d bytes long" % sk_len)

    # MLDSAKey checks that the seed, the expanded key and the public key match
    # (RFC 9881, Section 8.2)
    return MLDSAKey(param_set=param_set, seed=seed, sk=sk, pk=pk)


def import_key(
    encoded: Union[Buffer, str],
    passphrase: Optional[Union[bytes, str]] = None,
    *,
    max_iteration_count: Optional[int] = None,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> MLDSAKey:
    """Import an ML-DSA key (public or private), as defined in `RFC 9881`_.

    Args:
      encoded (bytes or string):
        The ML-DSA key to import, in DER format (``bytes``), or in PEM format
        (`RFC 7468`_, as a string or as ``bytes``). It can be:

        * For a **public** key: an X.509 ``SubjectPublicKeyInfo``,
          or an X.509 certificate (the signature of the certificate is not checked).
        * For a **private** key: a `PKCS#8`_ ``OneAsymmetricKey``
          (version 1 or 2, in the clear or encrypted).
          The private key can contain the seed, the expanded private key or both.

        The parameters of the ``AlgorithmIdentifier`` must be absent
        (or ``NULL``, which is tolerated).

        In PEM format, the label must match the content: ``PUBLIC KEY``,
        ``CERTIFICATE`` (or ``X509 CERTIFICATE``, ``X.509 CERTIFICATE``),
        ``PRIVATE KEY`` or ``ENCRYPTED PRIVATE KEY``.
        The legacy PEM encryption (with the ``Proc-Type`` header) is not supported.

        If the private key contains more than one among the seed,
        the expanded private key and the public key (in the ``publicKey`` field
        of a ``OneAsymmetricKey`` version 2), they must match.

      passphrase (bytes or string):
        The passphrase to decrypt an encrypted private key
        (`PKCS#8`_ ``EncryptedPrivateKeyInfo``).
        It is ignored if the key is not encrypted.

      max_iteration_count (integer):
        The maximum value allowed for the PBKDF2 iteration count or
        the scrypt cost *N·r·p/8* (that is, *N* for the usual *r=8* and *p=1*)
        of an encrypted private key.
        A malicious key could require an extremely high number of
        iterations, tying up the CPU for hours.
        The default value is None: a limit for each KDF, which keeps
        the key derivation to about one minute at most
        (see :ref:`the limits for decryption<pkcs8_limits>`).
        Set it to ``0`` to disable the check.

      threads (integer):
        The maximum number of threads used to derive the decryption key
        with scrypt (default: 1, no extra threads; 0 for all CPU cores).
        Only a private key protected with scrypt and a parallelization
        parameter larger than 1 can use them.

      max_memory (integer):
        The maximum memory (in bytes) for the key derivation of an encrypted
        private key, as a limit on the **total** of all threads together.
        The default value is None (a limit of 256 MiB).
        Set it to ``0`` to disable the check.

    Returns:
      :class:`MLDSAKey` : a new ML-DSA key object

    Raises:
      PassphraseRequiredError:
        (a ``ValueError``) when the private key is encrypted,
        but no passphrase was provided.
      IncorrectPassphraseError:
        (a ``ValueError``) when the private key cannot be decrypted
        with the passphrase (most likely, the passphrase is wrong).
      ValueError: when the key cannot be parsed, it is not an ML-DSA key,
        or its components do not match.

    .. _`RFC 9881`: https://www.rfc-editor.org/rfc/rfc9881.html
    .. _`PKCS#8`: https://www.rfc-editor.org/rfc/rfc5958.html
    .. _`RFC 7468`: https://www.rfc-editor.org/rfc/rfc7468.html
    """

    from Crypto.IO import PEM, PKCS8

    PKCS8._check_kdf_params(max_iteration_count, threads, max_memory)

    if isinstance(encoded, str):
        text = encoded
    else:
        encoded = bytes(encoded)
        if not encoded.lstrip().startswith(b"-----BEGIN "):
            key, _ = _import_der(encoded, passphrase, max_iteration_count, threads, max_memory)
            return key
        try:
            text = encoded.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("Not a valid PEM block") from None

    # PEM (RFC 7468)
    if "Proc-Type:" in text:
        raise ValueError("The legacy PEM encryption is not supported: encrypt the key with PKCS#8")
    der, label, _ = PEM.decode(text)
    if label in _CERTIFICATE_LABELS:
        label = "CERTIFICATE"
    if label not in ("PUBLIC KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "CERTIFICATE"):
        raise ValueError("Unsupported PEM label '%s'" % label)

    key, der_label = _import_der(der, passphrase, max_iteration_count, threads, max_memory)
    if der_label != label:
        raise ValueError("The PEM label '%s' does not match its content (%s)" % (label, der_label))
    return key
