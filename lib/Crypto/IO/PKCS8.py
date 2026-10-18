#
#  PublicKey/PKCS8.py : PKCS#8 functions
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Callable, Optional, Union

from Crypto import (
    _INCORRECT_PASSPHRASE,
    _PASSPHRASE_REQUIRED,
    IncorrectPassphraseError,
    KdfLimitError,
    PassphraseRequiredError,
)
from Crypto.IO._PBES import (
    PBES1,
    PBES2,
    PbesError,
    ProtParams,
)
from Crypto.Util._bytes import tobytes
from Crypto.Util._threads import threads_param
from Crypto.Util.asn1 import (
    ContextTag,
    DerBitString,
    DerNull,
    DerObject,
    DerObjectId,
    DerOctetString,
    DerSequence,
)

__all__ = ["wrap", "unwrap", "UnwrappedKey"]


#: Encryption scheme of a private key, when the ``protection`` is not specified
DEFAULT_PROTECTION = "PBKDF2WithHMAC-SHA256AndAES256-CBC"


class UnwrappedKey(tuple[str, bytes, Optional[bytes]]):
    """The result of :func:`unwrap`.

    It is a tuple ``(oid, private_key, params)``, so that it can be
    indexed or unpacked into three variables, and it has the attributes
    listed below.
    """

    #: The ``publicKey`` field of a ``OneAsymmetricKey`` version 2 (`RFC 5958`_),
    #: as bytes (the content of the BIT STRING), or ``None`` if it is absent.
    #: It is returned also if the version of the structure is 1,
    #: where the field is not allowed: it is up to the caller to reject it
    #: or to check that it matches the private key.
    public_key: Optional[bytes]

    @classmethod
    def _create(
        cls,
        oid: str,
        private_key: bytes,
        params: Optional[bytes],
        public_key: Optional[bytes],
    ) -> UnwrappedKey:
        result = cls((oid, private_key, params))
        result.public_key = public_key
        return result

    @property
    def oid(self) -> str:
        """The algorithm identifier of the wrapped key (OID, dotted string)."""
        return self[0]

    @property
    def private_key(self) -> bytes:
        """The private key (bytes, DER encoded)."""
        return self[1]

    @property
    def params(self) -> Optional[bytes]:
        """The ``parameters`` of the ``AlgorithmIdentifier`` (bytes, DER encoded),
        or ``None`` if they are absent or ``NULL``."""
        return self[2]

    def __repr__(self) -> str:
        return "UnwrappedKey(oid=%r, private_key=<%d bytes>, params=%r, public_key=%s)" % (
            self.oid,
            len(self.private_key),
            self.params,
            None if self.public_key is None else "<%d bytes>" % len(self.public_key),
        )


def _check_kdf_params(
    max_iteration_count: Optional[int] = None, threads: int = 1, max_memory: Optional[int] = None
) -> None:
    """Check the parameters that control the key derivation in :func:`wrap`
    and :func:`unwrap`.

    The functions that export and import keys call it upfront,
    so that an invalid value is reported even if the key is not encrypted.
    """

    for name, value in (("max_iteration_count", max_iteration_count), ("max_memory", max_memory)):
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError("'%s' must be an integer or None" % name)
            if value < 0:
                raise ValueError("'%s' must be a non-negative integer" % name)
    threads_param(threads)


def wrap(
    private_key: bytes,
    key_oid: str,
    passphrase: Optional[Union[bytes, str]] = None,
    protection: Optional[str] = None,
    prot_params: Optional[ProtParams] = None,
    key_params: Optional[DerObject] = DerNull(),  # noqa: B008
    randfunc: Optional[Callable[[int], bytes]] = None,
    *,
    threads: int = 1,
    public_key: Optional[bytes] = None,
) -> bytes:
    """Wrap a private key into a PKCS#8 blob (clear or encrypted).

    Args:

      private_key (bytes):
        The private key encoded in binary form. The actual encoding is
        algorithm specific. In most cases, it is DER.

      key_oid (string):
        The object identifier (OID) of the private key to wrap.
        It is a dotted string, like ``'1.2.840.113549.1.1.1'`` (for RSA keys)
        or ``'1.2.840.10045.2.1'`` (for ECC keys).

    Keyword Args:

      passphrase (bytes or string):
        The secret passphrase from which the wrapping key is derived.
        Set it only if encryption is required.

      protection (string):
        The identifier of the algorithm to use for securely wrapping the key.
        Refer to :ref:`the encryption parameters<enc_params>` .
        The default value is ``'PBKDF2WithHMAC-SHA256AndAES256-CBC'``.

      prot_params (dictionary):
        Parameters for the key derivation function (KDF).
        Refer to :ref:`the encryption parameters<enc_params>` .

      key_params (DER object or None):
        The ``parameters`` field to use in the ``AlgorithmIdentifier``
        SEQUENCE. If ``None``, no ``parameters`` field will be added.
        By default, the ASN.1 type ``NULL`` is used.

      randfunc (callable):
        Random number generation function; it should accept a single integer
        N and return a string of random data, N bytes long.
        If not specified, a new RNG will be instantiated
        from :mod:`Crypto.Random`.

      threads (integer):
        The maximum number of threads used to derive the wrapping key
        with scrypt (default: 1, no extra threads; 0 for all CPU cores).
        Only scrypt with a ``parallelization`` larger than 1 can use them.
        See :func:`Crypto.Protocol.KDF.scrypt`.

      public_key (bytes):
        The public key, to store in the field ``publicKey``.
        The actual encoding is algorithm specific.
        If set, the result is a ``OneAsymmetricKey`` version 2 (`RFC 5958`_),
        otherwise it is a ``PrivateKeyInfo`` (version 1, the default).

    Returns:
      bytes: The PKCS#8-wrapped private key (possibly encrypted).
    """

    _check_kdf_params(threads=threads)

    #
    #   OneAsymmetricKey ::= SEQUENCE {
    #       version                   Version,  -- v1(0) or v2(1)
    #       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    #       privateKey                PrivateKey,
    #       attributes            [0] IMPLICIT Attributes OPTIONAL,
    #       ...,
    #       [[2: publicKey        [1] IMPLICIT PublicKey OPTIONAL ]],
    #       ...
    #   }
    #
    if key_params is None:
        algorithm = DerSequence([DerObjectId(key_oid)])
    else:
        algorithm = DerSequence([DerObjectId(key_oid), key_params])

    if public_key is None:
        pk_info = DerSequence([0, algorithm, DerOctetString(private_key)])
    else:
        pk_info = DerSequence(
            [1, algorithm, DerOctetString(private_key), DerBitString(public_key, implicit=1)]
        )
    pk_info_der = pk_info.encode()

    if passphrase is None:
        return pk_info_der

    if not passphrase:
        raise ValueError("Empty passphrase")

    # Encryption with PBES2
    passphrase = tobytes(passphrase)
    if protection is None:
        protection = DEFAULT_PROTECTION
    return PBES2.encrypt(pk_info_der, passphrase, protection, prot_params, randfunc, threads=threads)


def unwrap(
    p8_private_key: bytes,
    passphrase: Optional[Union[bytes, str]] = None,
    max_iteration_count: Optional[int] = None,
    *,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> UnwrappedKey:
    """Unwrap a private key from a PKCS#8 blob (clear or encrypted).

    Args:
      p8_private_key (bytes):
        The private key wrapped into a PKCS#8 container, DER encoded.

    Keyword Args:
      passphrase (byte string or string):
        The passphrase to use to decrypt the blob (if it is encrypted).
      max_iteration_count (integer):
        The maximum value allowed for the PBKDF1/PBKDF2 iteration count,
        or for the scrypt cost *N·r·p/8* (that is, *N* for the usual *r=8* and *p=1*).
        An attacker could craft a malicious key blob that requires an
        extremely high number of iterations, tying up the CPU for hours.
        The default value is None: a limit for each KDF, which keeps
        the key derivation to about one minute at most
        (see :ref:`the limits for decryption<pkcs8_limits>`).
        Set it to ``0`` to disable the check.
      threads (integer):
        The maximum number of threads used to derive the unwrapping key
        with scrypt (default: 1, no extra threads; 0 for all CPU cores).
        Only a blob protected with scrypt and a parallelization parameter
        larger than 1 can use them.
        See :func:`Crypto.Protocol.KDF.scrypt`.
      max_memory (integer):
        The maximum memory (in bytes) for the key derivation, as a limit on
        the **total** of all threads together (not on each thread).
        Only scrypt uses a significant amount: 128 · (*N* + 2) · *r* bytes for
        **each** thread, plus 256 · *r* · *p* bytes for all the flows together.
        If the requested threads do not fit, fewer are used (down to one);
        if a single thread does not fit, :class:`Crypto.KdfMemoryLimitError` is raised.
        The default value is None (a limit of 256 MiB).
        Set it to ``0`` to disable the check.

    Return:
      :class:`UnwrappedKey`: a tuple containing

       #. the algorithm identifier of the wrapped key (OID, dotted string)
       #. the private key (bytes, DER encoded)
       #. the associated parameters (bytes, DER encoded) or ``None``
          (also if they are ``NULL``)

      with the same items as attributes, plus the attribute ``public_key``.

    Raises:
      PassphraseRequiredError : (a ``ValueError``) if the blob is encrypted
        and no passphrase has been provided
      IncorrectPassphraseError : (a ``ValueError``) if the blob cannot be
        decrypted with the passphrase (most likely, the passphrase is incorrect)
      KdfIterationLimitError : (a ``ValueError``) if the iteration count
        is above :data:`max_iteration_count`
      KdfMemoryLimitError : (a ``ValueError``) if the key derivation needs
        more memory than :data:`max_memory`
      ValueError : if decoding fails for any other reason
    """

    _check_kdf_params(max_iteration_count, threads, max_memory)

    # EncryptedPrivateKeyInfo ::= SEQUENCE {
    #     encryptionAlgorithm  AlgorithmIdentifier,
    #     encryptedData        OCTET STRING
    # }
    #
    # (a PrivateKeyInfo/OneAsymmetricKey starts with an INTEGER instead)
    pk_info = DerSequence().decode(p8_private_key, nr_elements=(2, 3, 4, 5))
    encrypted = pk_info.item_types() == [DerSequence, DerOctetString]

    if encrypted:
        if passphrase is None:
            raise PassphraseRequiredError(_PASSPHRASE_REQUIRED)
        passphrase = tobytes(passphrase)

        found = False
        try:
            p8_private_key = PBES1.decrypt(
                p8_private_key, passphrase, max_iteration_count=max_iteration_count
            )
            found = True
        except (KdfLimitError, IncorrectPassphraseError):
            # The key is well-formed, and these are the only reasons to reject it
            raise
        except PbesError as e:
            error_str = "PBES1[%s]" % str(e)
        except ValueError:
            error_str = "PBES1[Invalid]"

        if not found:
            try:
                p8_private_key = PBES2.decrypt(
                    p8_private_key,
                    passphrase,
                    max_iteration_count=max_iteration_count,
                    threads=threads,
                    max_memory=max_memory,
                )
                found = True
            except (KdfLimitError, IncorrectPassphraseError):
                raise
            except PbesError as e:
                error_str += ",PBES2[%s]" % str(e)
            except ValueError:
                error_str += ",PBES2[Invalid]"

        if not found:
            raise ValueError("Error decoding PKCS#8 (%s)" % error_str)

        # With an incorrect passphrase, the padding may still be correct by chance
        try:
            pk_info = DerSequence().decode(p8_private_key, nr_elements=(3, 4, 5))
        except ValueError:
            raise IncorrectPassphraseError(_INCORRECT_PASSPHRASE) from None
    elif len(pk_info) == 2:
        raise ValueError("Not a valid PKCS#8 structure")

    # RFC 5958 (PKCS#8), version is v1(0)
    #
    #   PrivateKeyInfo ::= SEQUENCE {
    #       version                 Version,
    #       privateKeyAlgorithm     PrivateKeyAlgorithmIdentifier,
    #       privateKey              PrivateKey,
    #       attributes              [0]  IMPLICIT Attributes OPTIONAL
    #   }
    #
    # RFC 5958, Asymmetric Key Package, version is v2(1)
    #
    #   OneAsymmetricKey ::= SEQUENCE {
    #       version                   Version,
    #       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    #       privateKey                PrivateKey,
    #       attributes            [0] IMPLICIT Attributes OPTIONAL,
    #       ...,
    #       [[2: publicKey        [1] IMPLICIT PublicKey OPTIONAL ]],
    #       ...
    #   }

    if pk_info[0] == 0:
        if len(pk_info) not in (3, 4):
            raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")
    elif pk_info[0] == 1:
        if len(pk_info) not in (3, 4, 5):
            raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")
    else:
        raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")

    algo = DerSequence().decode(pk_info[1], nr_elements=(1, 2))
    algo_oid = DerObjectId().decode(algo[0]).value
    algo_params = None if len(algo) == 1 else algo[1]

    # NULL parameters are treated as absent
    if algo_params is not None:
        try:
            DerNull().decode(algo_params)
            algo_params = None
        except Exception:
            pass

    # PrivateKey ::= OCTET STRING
    private_key = DerOctetString().decode(pk_info[2]).payload

    # We ignore attributes [0]
    # publicKey [1] IMPLICIT BIT STRING is only valid in v2,
    # but we return it in any case, so that the caller can check it
    public_key = None
    for item_type, item in zip(pk_info.item_types()[3:], pk_info[3:]):
        if item_type == ContextTag(1):
            public_key = DerBitString(implicit=1).decode(item, strict=True).value

    return UnwrappedKey._create(algo_oid, private_key, algo_params, public_key)
