# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""SLH-DSA keys (FIPS 205): the parameter sets, the key class,
and the functions to generate, build and import keys."""

from __future__ import annotations

import hmac
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, Optional, Union, overload

from Crypto.PublicKey import _create_subject_public_key_info, _extract_subject_public_key_info, _fips205
from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import tobytes
from Crypto.Util._threads import threads_param
from Crypto.Util._typing import RNG, Buffer, Message
from Crypto.Util.asn1 import DerBitString, DerInteger, DerNull, DerObjectId, DerOctetString, DerSequence

if TYPE_CHECKING:
    from Crypto.IO._PBES import ProtParams

__all__ = [
    "ParamSet",
    "SLH_DSA_SHA2_128s",
    "SLH_DSA_SHAKE_128s",
    "SLH_DSA_SHA2_128f",
    "SLH_DSA_SHAKE_128f",
    "SLH_DSA_SHA2_192s",
    "SLH_DSA_SHAKE_192s",
    "SLH_DSA_SHA2_192f",
    "SLH_DSA_SHAKE_192f",
    "SLH_DSA_SHA2_256s",
    "SLH_DSA_SHAKE_256s",
    "SLH_DSA_SHA2_256f",
    "SLH_DSA_SHAKE_256f",
    "SLH_DSA_SHA2_128_24",
    "SLH_DSA_SHAKE_128_24",
    "SLH_DSA_SHA2_192_24",
    "SLH_DSA_SHAKE_192_24",
    "SLH_DSA_SHA2_256_24",
    "SLH_DSA_SHAKE_256_24",
    "SLHDSAKey",
    "generate",
    "construct",
    "import_key",
]


class ParamSet(Enum):
    """The SLH-DSA parameter sets of FIPS 205 (Section 11), and those of
    the initial public draft of NIST SP 800-230 (Table 1).
    The value of each member is its name in FIPS 205 or SP 800-230.

    In FIPS 205, the ``s`` sets have small signatures and slow signing,
    the ``f`` sets have fast signing and larger signatures.

    The ``-24`` sets of SP 800-230 have smaller signatures and faster
    verification, but much slower signing and key generation (minutes),
    and each key must sign at most 2^24 messages.
    SP 800-230 is a draft: these sets may still change.
    Their support is experimental: do not use them in production.
    """

    SLH_DSA_SHA2_128s = "SLH-DSA-SHA2-128s"
    """NIST security category 1, SHA-256"""

    SLH_DSA_SHAKE_128s = "SLH-DSA-SHAKE-128s"
    """NIST security category 1, SHAKE256"""

    SLH_DSA_SHA2_128f = "SLH-DSA-SHA2-128f"
    """NIST security category 1, SHA-256"""

    SLH_DSA_SHAKE_128f = "SLH-DSA-SHAKE-128f"
    """NIST security category 1, SHAKE256"""

    SLH_DSA_SHA2_192s = "SLH-DSA-SHA2-192s"
    """NIST security category 3, SHA-256 and SHA-512"""

    SLH_DSA_SHAKE_192s = "SLH-DSA-SHAKE-192s"
    """NIST security category 3, SHAKE256"""

    SLH_DSA_SHA2_192f = "SLH-DSA-SHA2-192f"
    """NIST security category 3, SHA-256 and SHA-512"""

    SLH_DSA_SHAKE_192f = "SLH-DSA-SHAKE-192f"
    """NIST security category 3, SHAKE256"""

    SLH_DSA_SHA2_256s = "SLH-DSA-SHA2-256s"
    """NIST security category 5, SHA-256 and SHA-512"""

    SLH_DSA_SHAKE_256s = "SLH-DSA-SHAKE-256s"
    """NIST security category 5, SHAKE256"""

    SLH_DSA_SHA2_256f = "SLH-DSA-SHA2-256f"
    """NIST security category 5, SHA-256 and SHA-512"""

    SLH_DSA_SHAKE_256f = "SLH-DSA-SHAKE-256f"
    """NIST security category 5, SHAKE256"""

    SLH_DSA_SHA2_128_24 = "SLH-DSA-SHA2-128-24"
    """NIST security category 1, SHA-256, at most 2^24 signatures (draft SP 800-230, experimental)"""

    SLH_DSA_SHAKE_128_24 = "SLH-DSA-SHAKE-128-24"
    """NIST security category 1, SHAKE256, at most 2^24 signatures (draft SP 800-230, experimental)"""

    SLH_DSA_SHA2_192_24 = "SLH-DSA-SHA2-192-24"
    """NIST security category 3, SHA-256 and SHA-512, at most 2^24 signatures (draft SP 800-230, experimental)"""

    SLH_DSA_SHAKE_192_24 = "SLH-DSA-SHAKE-192-24"
    """NIST security category 3, SHAKE256, at most 2^24 signatures (draft SP 800-230, experimental)"""

    SLH_DSA_SHA2_256_24 = "SLH-DSA-SHA2-256-24"
    """NIST security category 5, SHA-256 and SHA-512, at most 2^24 signatures (draft SP 800-230, experimental)"""

    SLH_DSA_SHAKE_256_24 = "SLH-DSA-SHAKE-256-24"
    """NIST security category 5, SHAKE256, at most 2^24 signatures (draft SP 800-230, experimental)"""


# The members of ParamSet, also at the module level (SLHDSA.SLH_DSA_SHA2_128s)

#: Same as :attr:`ParamSet.SLH_DSA_SHA2_128s`
SLH_DSA_SHA2_128s = ParamSet.SLH_DSA_SHA2_128s
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_128s`
SLH_DSA_SHAKE_128s = ParamSet.SLH_DSA_SHAKE_128s
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_128f`
SLH_DSA_SHA2_128f = ParamSet.SLH_DSA_SHA2_128f
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_128f`
SLH_DSA_SHAKE_128f = ParamSet.SLH_DSA_SHAKE_128f
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_192s`
SLH_DSA_SHA2_192s = ParamSet.SLH_DSA_SHA2_192s
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_192s`
SLH_DSA_SHAKE_192s = ParamSet.SLH_DSA_SHAKE_192s
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_192f`
SLH_DSA_SHA2_192f = ParamSet.SLH_DSA_SHA2_192f
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_192f`
SLH_DSA_SHAKE_192f = ParamSet.SLH_DSA_SHAKE_192f
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_256s`
SLH_DSA_SHA2_256s = ParamSet.SLH_DSA_SHA2_256s
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_256s`
SLH_DSA_SHAKE_256s = ParamSet.SLH_DSA_SHAKE_256s
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_256f`
SLH_DSA_SHA2_256f = ParamSet.SLH_DSA_SHA2_256f
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_256f`
SLH_DSA_SHAKE_256f = ParamSet.SLH_DSA_SHAKE_256f
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_128_24`
SLH_DSA_SHA2_128_24 = ParamSet.SLH_DSA_SHA2_128_24
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_128_24`
SLH_DSA_SHAKE_128_24 = ParamSet.SLH_DSA_SHAKE_128_24
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_192_24`
SLH_DSA_SHA2_192_24 = ParamSet.SLH_DSA_SHA2_192_24
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_192_24`
SLH_DSA_SHAKE_192_24 = ParamSet.SLH_DSA_SHAKE_192_24
#: Same as :attr:`ParamSet.SLH_DSA_SHA2_256_24`
SLH_DSA_SHA2_256_24 = ParamSet.SLH_DSA_SHA2_256_24
#: Same as :attr:`ParamSet.SLH_DSA_SHAKE_256_24`
SLH_DSA_SHAKE_256_24 = ParamSet.SLH_DSA_SHAKE_256_24


# FIPS 205, Table 2, and SP 800-230, Table 1 (initial public draft, April 2026)
_params = {
    # Params(sha2, n, h, d, h', a, k, lg_w, m)
    # FIPS 205, Table 2
    ParamSet.SLH_DSA_SHA2_128s: _fips205.Params(True, 16, 63, 7, 9, 12, 14, 4, 30),
    ParamSet.SLH_DSA_SHAKE_128s: _fips205.Params(False, 16, 63, 7, 9, 12, 14, 4, 30),
    ParamSet.SLH_DSA_SHA2_128f: _fips205.Params(True, 16, 66, 22, 3, 6, 33, 4, 34),
    ParamSet.SLH_DSA_SHAKE_128f: _fips205.Params(False, 16, 66, 22, 3, 6, 33, 4, 34),
    ParamSet.SLH_DSA_SHA2_192s: _fips205.Params(True, 24, 63, 7, 9, 14, 17, 4, 39),
    ParamSet.SLH_DSA_SHAKE_192s: _fips205.Params(False, 24, 63, 7, 9, 14, 17, 4, 39),
    ParamSet.SLH_DSA_SHA2_192f: _fips205.Params(True, 24, 66, 22, 3, 8, 33, 4, 42),
    ParamSet.SLH_DSA_SHAKE_192f: _fips205.Params(False, 24, 66, 22, 3, 8, 33, 4, 42),
    ParamSet.SLH_DSA_SHA2_256s: _fips205.Params(True, 32, 64, 8, 8, 14, 22, 4, 47),
    ParamSet.SLH_DSA_SHAKE_256s: _fips205.Params(False, 32, 64, 8, 8, 14, 22, 4, 47),
    ParamSet.SLH_DSA_SHA2_256f: _fips205.Params(True, 32, 68, 17, 4, 9, 35, 4, 49),
    ParamSet.SLH_DSA_SHAKE_256f: _fips205.Params(False, 32, 68, 17, 4, 9, 35, 4, 49),
    # SP 800-230, Table 1: at most 2^24 signatures per key
    ParamSet.SLH_DSA_SHA2_128_24: _fips205.Params(True, 16, 22, 1, 22, 24, 6, 2, 21),
    ParamSet.SLH_DSA_SHAKE_128_24: _fips205.Params(False, 16, 22, 1, 22, 24, 6, 2, 21),
    ParamSet.SLH_DSA_SHA2_192_24: _fips205.Params(True, 24, 21, 1, 21, 25, 9, 3, 32),
    ParamSet.SLH_DSA_SHAKE_192_24: _fips205.Params(False, 24, 21, 1, 21, 25, 9, 3, 32),
    ParamSet.SLH_DSA_SHA2_256_24: _fips205.Params(True, 32, 21, 1, 21, 25, 12, 2, 41),
    ParamSet.SLH_DSA_SHAKE_256_24: _fips205.Params(False, 32, 21, 1, 21, 25, 12, 2, 41),
}


# id-slh-dsa-* (RFC 9909, Section 3), for pure SLH-DSA.
# The parameter sets of SP 800-230 have no OID yet.
# Before adding them: importing a private key checks PK.root, which for those
# parameter sets takes minutes (as long as generating the key). Anyone who can
# make an application import a PKCS#8 key could then keep it busy (DoS).
_oids = {
    ParamSet.SLH_DSA_SHA2_128s: "2.16.840.1.101.3.4.3.20",
    ParamSet.SLH_DSA_SHA2_128f: "2.16.840.1.101.3.4.3.21",
    ParamSet.SLH_DSA_SHA2_192s: "2.16.840.1.101.3.4.3.22",
    ParamSet.SLH_DSA_SHA2_192f: "2.16.840.1.101.3.4.3.23",
    ParamSet.SLH_DSA_SHA2_256s: "2.16.840.1.101.3.4.3.24",
    ParamSet.SLH_DSA_SHA2_256f: "2.16.840.1.101.3.4.3.25",
    ParamSet.SLH_DSA_SHAKE_128s: "2.16.840.1.101.3.4.3.26",
    ParamSet.SLH_DSA_SHAKE_128f: "2.16.840.1.101.3.4.3.27",
    ParamSet.SLH_DSA_SHAKE_192s: "2.16.840.1.101.3.4.3.28",
    ParamSet.SLH_DSA_SHAKE_192f: "2.16.840.1.101.3.4.3.29",
    ParamSet.SLH_DSA_SHAKE_256s: "2.16.840.1.101.3.4.3.30",
    ParamSet.SLH_DSA_SHAKE_256f: "2.16.840.1.101.3.4.3.31",
}

# id-hash-slh-dsa-* (RFC 9909, Section 3): keys for HashSLH-DSA only, with a fixed
# hash function. They cannot be used for pure SLH-DSA, so they are not supported.
_HASH_SLH_DSA_OIDS = ["2.16.840.1.101.3.4.3.%d" % i for i in range(35, 47)]


def _check_param_set(param_set: ParamSet) -> _fips205.Params:
    if not isinstance(param_set, ParamSet):
        raise TypeError("The parameter set must be a member of Crypto.PublicKey.SLHDSA.ParamSet")
    return _params[param_set]


class SLHDSAKey:
    r"""Class defining an SLH-DSA key (private or public).
    Do not instantiate directly.
    Use :func:`generate` or :func:`construct` instead.

    :ivar param_set: The parameter set.
    :vartype param_set: :class:`ParamSet`
    """

    _sk: Optional[bytes]
    _pk: bytes

    def __init__(
        self,
        *,
        param_set: ParamSet,
        sk: Optional[Buffer] = None,
        pk: Optional[Buffer] = None,
        threads: int = 1,
    ) -> None:
        """Create a new SLH-DSA key.

        Keywords:
          param_set : ParamSet
            The parameter set.
          sk : bytes
            The private key.
          pk : bytes
            The public key.
          threads : int
            The maximum number of threads to check the private key.

        At least one of ``sk`` and ``pk`` must be present.
        If both are present, they must match.
        """

        self._init_param_set(param_set)
        threads = threads_param(threads)
        n = self._params.n

        if sk is not None:
            sk = bytes(sk)
            if len(sk) != self._params.sk_len:
                raise ValueError("The private key must be %d bytes long" % self._params.sk_len)
            # SK.seed || SK.prf || PK.seed || PK.root:
            # the root must be the one of the hypertree of SK.seed and PK.seed
            self._sk, self._pk = _fips205.slh_keygen_internal(
                self._params, sk[:n], sk[n : 2 * n], sk[2 * n : 3 * n], threads
            )
            if not hmac.compare_digest(sk, self._sk):
                raise ValueError("Invalid SLH-DSA private key: PK.root is not correct")
        elif pk is not None:
            pk = bytes(pk)
            if len(pk) != self._params.pk_len:
                raise ValueError("The public key must be %d bytes long" % self._params.pk_len)
            self._pk = pk
            return
        else:
            raise ValueError("At least one of 'sk' and 'pk' must be specified")

        if pk is not None and bytes(pk) != self._pk:
            raise ValueError("The private and the public keys do not match")

    @classmethod
    def _from_seeds(
        cls, param_set: ParamSet, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes, threads: int = 1
    ) -> SLHDSAKey:
        """Build a key from the three seeds with slh_keygen_internal
        (FIPS 205, Algorithm 18)."""

        key = cls.__new__(cls)
        key._init_param_set(param_set)
        threads = threads_param(threads)
        for seed in (sk_seed, sk_prf, pk_seed):
            if len(seed) != key._params.n:
                raise ValueError("The seeds must be %d bytes long" % key._params.n)
        key._sk, key._pk = _fips205.slh_keygen_internal(key._params, sk_seed, sk_prf, pk_seed, threads)
        return key

    def _init_param_set(self, param_set: ParamSet) -> None:
        """Set the parameter set of a new key (without its private key)."""

        self._params = _check_param_set(param_set)
        self.param_set = param_set
        self._sk = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SLHDSAKey):
            return False

        if other.has_private() != self.has_private():
            return False

        return other.param_set == self.param_set and other._pk == self._pk

    def __repr__(self) -> str:
        return "SLHDSAKey(param_set=%s, private=%s)" % (self.param_set, self.has_private())

    def __getstate__(self) -> dict[str, Any]:
        # A private key must not end up in a pickle (unencrypted, and executable on load)
        if self.has_private():
            from pickle import PicklingError

            raise PicklingError("A private SLH-DSA key cannot be pickled")
        return self.__dict__.copy()

    def has_private(self) -> bool:
        """``True`` if this key can be used for making signatures."""

        return self._sk is not None

    @property
    def sk(self) -> bytes:
        """The private key, encoded as in FIPS 205 (Figure 15):
        SK.seed, SK.prf, PK.seed and PK.root, each *n* bytes long."""

        if self._sk is None:
            raise ValueError("This is not a private SLH-DSA key")
        return self._sk

    @property
    def pk(self) -> bytes:
        """The public key, encoded as in FIPS 205 (Figure 16):
        PK.seed and PK.root, each *n* bytes long."""

        return self._pk

    def public_key(self) -> SLHDSAKey:
        """A matching SLH-DSA public key.

        Returns:
            a new :class:`SLHDSAKey` object
        """

        return SLHDSAKey(param_set=self.param_set, pk=self._pk)

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
        """Export this SLH-DSA key, as defined in `RFC 9909`_ (for pure SLH-DSA).

        A public key is encoded as an X.509 ``SubjectPublicKeyInfo``.

        A private key is encoded as a `PKCS#8`_ ``OneAsymmetricKey``
        (in the clear, or encrypted if ``passphrase`` is set),
        which contains the private key of FIPS 205 (:attr:`sk`).

        The parameter sets of SP 800-230 have no OID yet:
        their keys cannot be exported (:class:`ValueError`).

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

        .. _`RFC 9909`: https://www.rfc-editor.org/rfc/rfc9909.html
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

        if self.param_set not in _oids:
            raise ValueError("%s keys cannot be exported: there is no OID yet" % self.param_set.value)
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
            # SubjectPublicKeyInfo, without parameters (RFC 9909, Section 5),
            # with PK.seed || PK.root in the BIT STRING
            return _create_subject_public_key_info(oid, self._pk, None)

        PKCS8._check_kdf_params(threads=threads)
        if passphrase is not None:
            passphrase = tobytes(passphrase)
            if not passphrase:
                raise ValueError("Empty passphrase")
        elif protection is not None or prot_params is not None:
            raise ValueError("'protection' and 'prot_params' require a passphrase")

        # The privateKey OCTET STRING contains SK.seed || SK.prf || PK.seed || PK.root,
        # without any other ASN.1 wrapping (RFC 9909, Section 7)
        assert self._sk is not None
        return PKCS8.wrap(
            self._sk,
            oid,
            passphrase,
            protection,
            prot_params,
            key_params=None,
            randfunc=randfunc,
            threads=threads,
        )

    def _sign(self, M: Message, addrnd: Optional[bytes], threads: int = 1) -> bytes:
        """slh_sign_internal (FIPS 205, Algorithm 19).

        The message M is the concatenation of the pieces in the tuple ``M``.
        ``addrnd`` is the *n*-byte randomness (``None`` for the deterministic variant).
        ``threads`` is the maximum number of threads (0 for all CPU cores).
        """

        _check_message(M)
        if self._sk is None:
            raise TypeError("This is not a private SLH-DSA key")
        if addrnd is not None and len(addrnd) != self._params.n:
            raise ValueError("The randomness addrnd must be %d bytes long" % self._params.n)
        threads = threads_param(threads)
        return _fips205.slh_sign_internal(self._params, M, self._sk, addrnd, threads)

    def _verify(self, M: Message, signature: Buffer) -> bool:
        """slh_verify_internal (FIPS 205, Algorithm 20).

        The message M is as for :meth:`_sign`.

        Return ``True`` if the signature is valid, ``False`` otherwise.
        """

        _check_message(M)
        return _fips205.slh_verify_internal(self._params, M, bytes(signature), self._pk)


def _check_message(M: Message) -> None:
    if not isinstance(M, tuple):
        raise TypeError("The message must be a tuple of pieces to concatenate")


def generate(*, param_set: ParamSet, randfunc: Optional[RNG] = None, threads: int = 1) -> SLHDSAKey:
    """Generate a new SLH-DSA private key (FIPS 205, Algorithm 21).

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``SLHDSA.SLH_DSA_SHA2_128s``.

      randfunc (callable):
        Optional. The RNG to read the three seeds from (SK.seed, SK.prf and PK.seed,
        *n* bytes each, in this order).
        If ``None``, :func:`Crypto.Random.get_random_bytes` is used.

      threads (integer):
        Optional. The maximum number of threads used to generate the key
        (default: 1, no extra threads; 0 for all CPU cores).
        The key does not depend on the number of threads.

    Returns:
      :class:`SLHDSAKey` : a new private key
    """

    if randfunc is None:
        randfunc = get_random_bytes
    n = _check_param_set(param_set).n
    threads_param(threads)
    sk_seed = randfunc(n)
    sk_prf = randfunc(n)
    pk_seed = randfunc(n)
    return SLHDSAKey._from_seeds(param_set, sk_seed, sk_prf, pk_seed, threads)


def construct(
    *,
    param_set: ParamSet,
    sk: Optional[Buffer] = None,
    pk: Optional[Buffer] = None,
    threads: int = 1,
) -> SLHDSAKey:
    """Build an SLH-DSA key (private or public) from its components.

    Args:
      param_set (:class:`ParamSet`):
        Mandatory. The parameter set, for instance ``SLHDSA.SLH_DSA_SHA2_128s``.

      sk (bytes):
        The private key, encoded as in FIPS 205 (4 *n* bytes).
        Its consistency is checked: its PK.root must be the root of the hypertree,
        which takes as long as generating a key.

      pk (bytes):
        The public key, encoded as in FIPS 205 (2 *n* bytes).

      threads (integer):
        The maximum number of threads used to check the private key
        (default: 1, no extra threads; 0 for all CPU cores).

    At least one of ``sk`` and ``pk`` must be present.
    If both are present, they must match, otherwise :class:`ValueError` is raised.

    Returns:
      :class:`SLHDSAKey` : a new SLH-DSA key object
    """

    return SLHDSAKey(param_set=param_set, sk=sk, pk=pk, threads=threads)


# The PEM labels for a certificate (RFC 7468, Section 5.1)
_CERTIFICATE_LABELS = ("CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE")


def _param_set_from_oid(oid: str) -> ParamSet:
    for param_set, ps_oid in _oids.items():
        if ps_oid == oid:
            return param_set
    if oid in _HASH_SLH_DSA_OIDS:
        raise ValueError("HashSLH-DSA keys (OID %s) are not supported" % oid)
    raise ValueError("Not an SLH-DSA key (OID %s)" % oid)


def _import_subject_public_key_info(encoded: bytes) -> SLHDSAKey:
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #   algorithm         AlgorithmIdentifier,
    #   subjectPublicKey  BIT STRING }
    spki = DerSequence().decode(encoded, nr_elements=2, strict=True)
    algo = DerSequence().decode(spki[0], nr_elements=(1, 2), strict=True)
    param_set = _param_set_from_oid(DerObjectId().decode(algo[0], strict=True).value)
    # The parameters must be absent (RFC 9909, Section 3), but we also accept NULL
    if len(algo) != 1 and algo[1] != DerNull().encode():
        raise ValueError("The parameters of an SLH-DSA AlgorithmIdentifier must be absent")
    pk = DerBitString().decode(spki[1], strict=True).value
    return SLHDSAKey(param_set=param_set, pk=pk)


def _import_der(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> tuple[SLHDSAKey, str]:
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

    raise ValueError("Not a DER-encoded SLH-DSA key")


def _import_pkcs8(
    encoded: bytes,
    passphrase: Optional[Union[bytes, str]],
    max_iteration_count: Optional[int],
    threads: int,
    max_memory: Optional[int],
) -> SLHDSAKey:
    from Crypto.IO import PKCS8

    unwrapped = PKCS8.unwrap(encoded, passphrase, max_iteration_count, threads=threads, max_memory=max_memory)
    oid, sk, pk = unwrapped.oid, unwrapped.private_key, unwrapped.public_key
    param_set = _param_set_from_oid(oid)
    # The parameters must be absent (RFC 9909, Section 3), but NULL is accepted too
    if unwrapped.params is not None:
        raise ValueError("The parameters of an SLH-DSA AlgorithmIdentifier must be absent")

    # The privateKey OCTET STRING contains SK.seed || SK.prf || PK.seed || PK.root
    # (RFC 9909, Section 7)
    sk_len = _params[param_set].sk_len
    if len(sk) != sk_len:
        raise ValueError("Invalid SLH-DSA private key: it must be %d bytes long" % sk_len)

    # SLHDSAKey checks that PK.root is correct, and that the public key
    # (in a OneAsymmetricKey version 2) matches
    return SLHDSAKey(param_set=param_set, sk=sk, pk=pk, threads=threads)


def import_key(
    encoded: Union[Buffer, str],
    passphrase: Optional[Union[bytes, str]] = None,
    *,
    max_iteration_count: Optional[int] = None,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> SLHDSAKey:
    """Import an SLH-DSA key (public or private), as defined in `RFC 9909`_
    (for pure SLH-DSA).

    Args:
      encoded (bytes or string):
        The SLH-DSA key to import, in DER format (``bytes``), or in PEM format
        (`RFC 7468`_, as a string or as ``bytes``). It can be:

        * For a **public** key: an X.509 ``SubjectPublicKeyInfo``,
          or an X.509 certificate (the signature of the certificate is not checked).
        * For a **private** key: a `PKCS#8`_ ``OneAsymmetricKey``
          (version 1 or 2, in the clear or encrypted).

        The OID must be one of ``id-slh-dsa-*``: the keys for HashSLH-DSA only
        (``id-hash-slh-dsa-*``) are not supported.
        The parameters of the ``AlgorithmIdentifier`` must be absent
        (or ``NULL``, which is tolerated).

        In PEM format, the label must match the content: ``PUBLIC KEY``,
        ``CERTIFICATE`` (or ``X509 CERTIFICATE``, ``X.509 CERTIFICATE``),
        ``PRIVATE KEY`` or ``ENCRYPTED PRIVATE KEY``.
        The legacy PEM encryption (with the ``Proc-Type`` header) is not supported.

        A private key is checked as with :func:`construct`
        (its PK.root must be the root of the hypertree), which takes as long
        as generating a key. If it also contains the public key
        (in the ``publicKey`` field of a ``OneAsymmetricKey`` version 2),
        it must match.

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
        The maximum number of threads used to check a private key, and
        to derive the decryption key with scrypt
        (default: 1, no extra threads; 0 for all CPU cores).
        For scrypt, only a private key protected with a parallelization
        parameter larger than 1 can use them.

      max_memory (integer):
        The maximum memory (in bytes) for the key derivation of an encrypted
        private key, as a limit on the **total** of all threads together.
        The default value is None (a limit of 256 MiB).
        Set it to ``0`` to disable the check.

    Returns:
      :class:`SLHDSAKey` : a new SLH-DSA key object

    Raises:
      PassphraseRequiredError:
        (a ``ValueError``) when the private key is encrypted,
        but no passphrase was provided.
      IncorrectPassphraseError:
        (a ``ValueError``) when the private key cannot be decrypted
        with the passphrase (most likely, the passphrase is wrong).
      ValueError: when the key cannot be parsed, it is not an SLH-DSA key
        (or it is a HashSLH-DSA key), or its components do not match.

    .. _`RFC 9909`: https://www.rfc-editor.org/rfc/rfc9909.html
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
