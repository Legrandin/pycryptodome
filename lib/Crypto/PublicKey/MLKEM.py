# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""ML-KEM keys (FIPS 203): the parameter sets, the key class,
and the functions to generate, build and import keys."""

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
    "ML_KEM_512",
    "ML_KEM_768",
    "ML_KEM_1024",
    "MLKEMKey",
    "generate",
    "construct",
    "import_key",
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
    ek_len: int
    expanded_dk_len: int
    ct_len: int


# FIPS 203, Tables 2 and 3
_sizes = {
    ParamSet.ML_KEM_512: _Sizes(512, 2, 800, 1632, 768),
    ParamSet.ML_KEM_768: _Sizes(768, 3, 1184, 2400, 1088),
    ParamSet.ML_KEM_1024: _Sizes(1024, 4, 1568, 3168, 1568),
}

# id-alg-ml-kem-* (RFC 9935, Section 3)
_oids = {
    ParamSet.ML_KEM_512: "2.16.840.1.101.3.4.4.1",
    ParamSet.ML_KEM_768: "2.16.840.1.101.3.4.4.2",
    ParamSet.ML_KEM_1024: "2.16.840.1.101.3.4.4.3",
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
        expanded_dk: Optional[Buffer] = None,
        ek: Optional[Buffer] = None,
    ) -> None:
        """Create a new ML-KEM key.

        Keywords:
          param_set : ParamSet
            The parameter set.
          seed : bytes
            The 64-byte seed of the private key (d || z).
          expanded_dk : bytes
            The expanded decapsulation key (the private key).
          ek : bytes
            The encapsulation key (the public key).

        At least one of ``seed``, ``expanded_dk`` and ``ek`` must be present.
        If more than one is present, they must match.
        """

        self._ps = _check_param_set(param_set)
        self.param_set = param_set

        self._seed: Optional[bytes] = None
        self._expanded_dk: Optional[bytes] = None

        if seed is not None:
            seed = bytes(seed)
            if len(seed) != _SEED_LEN:
                raise ValueError("The seed must be %d bytes long" % _SEED_LEN)
            self._seed = seed
            self._ek, self._expanded_dk = self._keypair(seed)
            if expanded_dk is not None and not hmac.compare_digest(bytes(expanded_dk), self._expanded_dk):
                raise ValueError("The seed and the expanded private key do not match")
        elif expanded_dk is not None:
            expanded_dk = bytes(expanded_dk)
            if len(expanded_dk) != self._ps.expanded_dk_len:
                raise ValueError("The expanded private key must be %d bytes long" % self._ps.expanded_dk_len)
            self._check(_raw_mlkem_lib.mlkem_check_sk, expanded_dk, "private")
            self._expanded_dk = expanded_dk
            # dk = dk_PKE || ek || H(ek) || z (FIPS 203, Algorithm 16)
            self._ek = expanded_dk[384 * self._ps.k : 768 * self._ps.k + 32]
            self._pairwise_check()
        elif ek is not None:
            ek = bytes(ek)
            if len(ek) != self._ps.ek_len:
                raise ValueError("The public key must be %d bytes long" % self._ps.ek_len)
            self._check(_raw_mlkem_lib.mlkem_check_pk, ek, "public")
            self._ek = ek
            return
        else:
            raise ValueError("At least one of 'seed', 'expanded_dk' and 'ek' must be specified")

        if ek is not None and bytes(ek) != self._ek:
            raise ValueError("The private and the public keys do not match")

    def _keypair(self, seed: bytes) -> tuple[bytes, bytes]:
        """ML-KEM.KeyGen_internal (FIPS 203, Algorithm 16): return (ek, expanded dk) for the seed d || z"""

        ek = create_string_buffer(self._ps.ek_len)
        expanded_dk = create_string_buffer(self._ps.expanded_dk_len)
        seed_ptr, seed_len = c_uint8_ptr_len(seed)
        result = _raw_mlkem_lib.mlkem_keypair(
            self._ps.level,
            ek,
            c_size_t(self._ps.ek_len),
            expanded_dk,
            c_size_t(self._ps.expanded_dk_len),
            seed_ptr,
            c_size_t(seed_len),
        )
        if result:
            raise ValueError("Error %d while generating an ML-KEM key" % result)
        return get_raw_buffer(ek), get_raw_buffer(expanded_dk)

    def _pairwise_check(self) -> None:
        # The hash check does not detect a corrupted dk_PKE (RFC 9935, Appendix C.4):
        # encapsulate with ek, and check that dk recovers the same shared secret
        ss, ct = self._encaps()
        if not hmac.compare_digest(self._decaps(ct), ss):
            raise ValueError("Invalid ML-KEM private key: the pairwise consistency check failed")

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

        return other.param_set == self.param_set and other._ek == self._ek

    def __repr__(self) -> str:
        return "MLKEMKey(param_set=%s, private=%s)" % (self.param_set, self.has_private())

    def __getstate__(self) -> dict[str, Any]:
        # A private key must not end up in a pickle (unencrypted, and executable on load)
        if self.has_private():
            from pickle import PicklingError

            raise PicklingError("A private ML-KEM key cannot be pickled: use export_key()")
        return self.__dict__.copy()

    def has_private(self) -> bool:
        """``True`` if this is a private key."""

        return self._expanded_dk is not None

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
    def expanded_dk(self) -> bytes:
        """The expanded decapsulation key (*dk* in FIPS 203, Algorithm 16)."""

        if self._expanded_dk is None:
            raise ValueError("This is not a private ML-KEM key")
        return self._expanded_dk

    @property
    def ek(self) -> bytes:
        """The encapsulation key, that is, the public key (*ek* in FIPS 203, Algorithm 16)."""

        return self._ek

    def public_key(self) -> MLKEMKey:
        """A matching ML-KEM public key.

        Returns:
            a new :class:`MLKEMKey` object
        """

        return MLKEMKey(param_set=self.param_set, ek=self._ek)

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
        """Export this ML-KEM key, as defined in `RFC 9935`_.

        A public key is encoded as an X.509 ``SubjectPublicKeyInfo``.

        A private key is encoded as a `PKCS#8`_ ``OneAsymmetricKey``
        (in the clear, or encrypted if ``passphrase`` is set).
        It contains the 64-byte seed (the format recommended by RFC 9935),
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

        .. _`RFC 9935`: https://www.rfc-editor.org/rfc/rfc9935.html
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
            # SubjectPublicKeyInfo, without parameters (RFC 9935, Sections 3 and 4)
            return _create_subject_public_key_info(oid, self._ek, None)

        PKCS8._check_kdf_params(threads=threads)
        if passphrase is not None:
            passphrase = tobytes(passphrase)
            if not passphrase:
                raise ValueError("Empty passphrase")
        elif protection is not None or prot_params is not None:
            raise ValueError("'protection' and 'prot_params' require a passphrase")

        # ML-KEM-PrivateKey ::= CHOICE {
        #   seed [0] OCTET STRING (SIZE (64)),
        #   expandedKey OCTET STRING,
        #   both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
        #
        # We write the seed if we know it, otherwise the expanded key
        if self._seed is not None:
            private_key = DerOctetString(self._seed, implicit=0).encode()
        else:
            assert self._expanded_dk is not None
            private_key = DerOctetString(self._expanded_dk).encode()

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
        ek_ptr, ek_len = c_uint8_ptr_len(self._ek)
        coins_ptr, coins_len = c_uint8_ptr_len(coins)
        result = _raw_mlkem_lib.mlkem_encaps(
            self._ps.level,
            ct,
            c_size_t(self._ps.ct_len),
            ss,
            c_size_t(_SS_LEN),
            ek_ptr,
            c_size_t(ek_len),
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

        if self._expanded_dk is None:
            raise TypeError("This is not a private ML-KEM key")
        if len(ct) != self._ps.ct_len:
            raise ValueError("The ML-KEM ciphertext must be %d bytes long" % self._ps.ct_len)

        ss = create_string_buffer(_SS_LEN)
        ct_ptr, ct_len = c_uint8_ptr_len(ct)
        dk_ptr, dk_len = c_uint8_ptr_len(self._expanded_dk)
        result = _raw_mlkem_lib.mlkem_decaps(
            self._ps.level,
            ss,
            c_size_t(_SS_LEN),
            ct_ptr,
            c_size_t(ct_len),
            dk_ptr,
            c_size_t(dk_len),
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
    expanded_dk: Optional[Buffer] = None,
    ek: Optional[Buffer] = None,
) -> MLKEMKey:
    """Build an ML-KEM key (private or public) from its components.

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``MLKEM.ML_KEM_768``.

      seed (bytes):
        The 64-byte seed of a private key: :math:`d \\| z` in FIPS 203
        (the input of ``ML-KEM.KeyGen_internal``, Algorithm 16).

      expanded_dk (bytes):
        The expanded decapsulation key (*dk* in FIPS 203).
        It must pass the hash check of FIPS 203 (Section 7.3),
        and a pairwise consistency check (an encapsulation and a decapsulation),
        unless the seed is also present.

      ek (bytes):
        The encapsulation key, that is, the public key (*ek* in FIPS 203).
        It must pass the modulus check of FIPS 203 (Section 7.2).

    At least one of ``seed``, ``expanded_dk`` and ``ek`` must be present.
    If more than one is present, they must match, otherwise :class:`ValueError` is raised.

    Returns:
      :class:`MLKEMKey` : a new ML-KEM key object
    """

    return MLKEMKey(param_set=param_set, seed=seed, expanded_dk=expanded_dk, ek=ek)


# The PEM labels for a certificate (RFC 7468, Section 5.1)
_CERTIFICATE_LABELS = ("CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE")


def _param_set_from_oid(oid: str) -> ParamSet:
    for param_set, ps_oid in _oids.items():
        if ps_oid == oid:
            return param_set
    raise ValueError("Not an ML-KEM key (OID %s)" % oid)


def _import_subject_public_key_info(encoded: bytes) -> MLKEMKey:
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #   algorithm         AlgorithmIdentifier,
    #   subjectPublicKey  BIT STRING }
    spki = DerSequence().decode(encoded, nr_elements=2, strict=True)
    algo = DerSequence().decode(spki[0], nr_elements=(1, 2), strict=True)
    param_set = _param_set_from_oid(DerObjectId().decode(algo[0], strict=True).value)
    # The parameters must be absent (RFC 9935, Section 3), but we also accept NULL
    if len(algo) != 1 and algo[1] != DerNull().encode():
        raise ValueError("The parameters of an ML-KEM AlgorithmIdentifier must be absent")
    ek = DerBitString().decode(spki[1], strict=True).value
    return MLKEMKey(param_set=param_set, ek=ek)


def _import_der(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> tuple[MLKEMKey, str]:
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

    raise ValueError("Not a DER-encoded ML-KEM key")


def _decode_private_key_choice(private_key: bytes) -> tuple[Optional[bytes], Optional[bytes]]:
    """Decode an ML-KEM-PrivateKey into the seed and the expanded private key
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
        expanded_dk = DerOctetString().decode(both[1], strict=True).payload
        return seed, expanded_dk
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid ML-KEM private key: unknown format")


def _import_pkcs8(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> MLKEMKey:
    from Crypto.IO import PKCS8

    unwrapped = PKCS8.unwrap(encoded, passphrase, max_iteration_count, threads=threads, max_memory=max_memory)
    oid, private_key, ek = unwrapped.oid, unwrapped.private_key, unwrapped.public_key
    param_set = _param_set_from_oid(oid)
    # The parameters must be absent (RFC 9935, Section 3), but NULL is accepted too
    if unwrapped.params is not None:
        raise ValueError("The parameters of an ML-KEM AlgorithmIdentifier must be absent")
    expanded_dk_len = _sizes[param_set].expanded_dk_len

    # ML-KEM-PrivateKey ::= CHOICE {
    #   seed [0] OCTET STRING (SIZE (64)),
    #   expandedKey OCTET STRING,
    #   both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }
    #
    # The tag selects the alternative (RFC 9935, Section 6)
    seed, expanded_dk = _decode_private_key_choice(private_key)

    if seed is not None and len(seed) != _SEED_LEN:
        raise ValueError("Invalid ML-KEM private key: the seed must be %d bytes long" % _SEED_LEN)
    if expanded_dk is not None and len(expanded_dk) != expanded_dk_len:
        raise ValueError(
            "Invalid ML-KEM private key: the expanded key must be %d bytes long" % expanded_dk_len
        )

    # MLKEMKey checks that the seed, the expanded key and the public key match
    # (RFC 9935, Section 8)
    return MLKEMKey(param_set=param_set, seed=seed, expanded_dk=expanded_dk, ek=ek)


def import_key(
    encoded: Union[Buffer, str],
    passphrase: Optional[Union[bytes, str]] = None,
    *,
    max_iteration_count: Optional[int] = None,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> MLKEMKey:
    """Import an ML-KEM key (public or private), as defined in `RFC 9935`_.

    Args:
      encoded (bytes or string):
        The ML-KEM key to import, in DER format (``bytes``), or in PEM format
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

        The same checks as in :func:`construct` apply.
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
      :class:`MLKEMKey` : a new ML-KEM key object

    Raises:
      PassphraseRequiredError:
        (a ``ValueError``) when the private key is encrypted,
        but no passphrase was provided.
      IncorrectPassphraseError:
        (a ``ValueError``) when the private key cannot be decrypted
        with the passphrase (most likely, the passphrase is wrong).
      ValueError: when the key cannot be parsed, it is not an ML-KEM key,
        it fails the checks, or its components do not match.

    .. _`RFC 9935`: https://www.rfc-editor.org/rfc/rfc9935.html
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
