from __future__ import annotations

import struct
from enum import IntEnum
from types import ModuleType
from typing import TYPE_CHECKING, Optional, Union

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import ECC, MLKEM, Hybrid
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey.Hybrid import HybridKey
from Crypto.PublicKey.MLKEM import MLKEMKey
from Crypto.Util.strxor import strxor

from .DH import import_x448_public_key, import_x25519_public_key, key_agreement
from .KDF import _HKDF_expand, _HKDF_extract

if TYPE_CHECKING:
    from Crypto.Cipher._mode_gcm import GcmMode
    from Crypto.Cipher.ChaCha20_Poly1305 import ChaCha20Poly1305Cipher


class MODE(IntEnum):
    """HPKE modes"""

    BASE = 0x00
    PSK = 0x01
    AUTH = 0x02
    AUTH_PSK = 0x03


class AEAD(IntEnum):
    """The symmetric ciphers of HPKE (Authenticated Encryption with Associated Data, AEAD),
    for the parameter ``aead_id`` of :func:`new`.
    The value of each member is its HPKE identifier."""

    AES128_GCM = 0x0001
    """AES-128 in GCM mode"""

    AES256_GCM = 0x0002
    """AES-256 in GCM mode"""

    CHACHA20_POLY1305 = 0x0003
    """ChaCha20-Poly1305"""

    EXPORT_ONLY = 0xFFFF
    """No cipher, so the HPKE context can only export secrets (see :meth:`HPKE_Cipher.export`)"""


class DeserializeError(ValueError):
    pass


class MessageLimitReachedError(ValueError):
    pass


# The keys that HPKE can use
KemKey = Union[EccKey, MLKEMKey, HybridKey]

# CURVE to (KEM ID, KDF ID, HASH)
_Curve_Config = {
    "NIST P-256": (0x0010, 0x0001, SHA256),
    "NIST P-384": (0x0011, 0x0002, SHA384),
    "NIST P-521": (0x0012, 0x0003, SHA512),
    "Curve25519": (0x0020, 0x0001, SHA256),
    "Curve448": (0x0021, 0x0003, SHA512),
}

# Parameter set of ML-KEM (draft-ietf-hpke-pq, Section 3) or of
# a hybrid KEM (draft-ietf-hpke-pq, Section 4) to (KEM ID, KDF ID, HASH)
_PQ_Config = {
    MLKEM.ML_KEM_512: (0x0040, 0x0001, SHA256),
    MLKEM.ML_KEM_768: (0x0041, 0x0001, SHA256),
    MLKEM.ML_KEM_1024: (0x0042, 0x0002, SHA384),
    Hybrid.MLKEM768_X25519: (0x647A, 0x0001, SHA256),
}


def _kem_config(key: KemKey) -> tuple[int, int, ModuleType]:
    """Return the KEM ID, the KDF ID and the hash of the KDF for a key"""

    if isinstance(key, (MLKEMKey, HybridKey)):
        return _PQ_Config[key.param_set]
    if not isinstance(key, EccKey):
        raise TypeError("The HPKE keys must be ECC, ML-KEM or hybrid keys")
    try:
        return _Curve_Config[key.curve]
    except KeyError as ke:
        raise ValueError(f"Curve {key.curve} is not supported by HPKE") from ke


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes, hashmod: ModuleType) -> bytes:
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return _HKDF_extract(salt, labeled_ikm, hashmod)


def _labeled_expand(
    prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes, hashmod: ModuleType
) -> bytes:
    labeled_info = struct.pack(">H", L) + b"HPKE-v1" + suite_id + label + info
    return _HKDF_expand(prk, labeled_info, L, hashmod)


def _extract_and_expand(dh: bytes, kem_context: bytes, suite_id: bytes, hashmod: ModuleType) -> bytes:
    Nsecret = hashmod.digest_size

    eae_prk = _labeled_extract(b"", b"eae_prk", dh, suite_id, hashmod)

    shared_secret = _labeled_expand(eae_prk, b"shared_secret", kem_context, Nsecret, suite_id, hashmod)
    return shared_secret


class HPKE_Cipher:
    """An HPKE context, to seal or unseal messages, or to export secrets.

    Do not instantiate directly: use :func:`new` instead.
    """

    def __init__(
        self,
        receiver_key: KemKey,
        enc: Optional[bytes],
        sender_key: Optional[EccKey],
        psk_pair: tuple[bytes, bytes],
        info: bytes,
        aead_id: AEAD,
        mode: MODE,
    ) -> None:
        self.enc: bytes = b"" if enc is None else enc
        """The encapsulated session key."""

        self._verify_psk_inputs(mode, psk_pair)

        self._aead_id = aead_id
        self._mode = mode

        self._kem_id, self._kdf_id, self._hashmod = _kem_config(receiver_key)

        self._suite_id = b"HPKE" + struct.pack(">HHH", self._kem_id, self._kdf_id, self._aead_id)
        self._Nk = 16 if self._aead_id == AEAD.AES128_GCM else 32
        self._Nn = 12
        self._Nt = 16
        self._Nh = self._hashmod.digest_size

        self._encrypt = not receiver_key.has_private()

        if self._encrypt:
            # SetupBaseS (encryption)
            if enc is not None:
                raise ValueError("Parameter 'enc' cannot be an input  when sealing")
            if isinstance(receiver_key, EccKey):
                shared_secret, self.enc = self._encap(receiver_key, self._kem_id, self._hashmod, sender_key)
            else:
                shared_secret, self.enc = self._encap_pq(receiver_key)
        else:
            # SetupBaseR (decryption)
            if enc is None:
                raise ValueError("Parameter 'enc' required when unsealing")
            if isinstance(receiver_key, EccKey):
                shared_secret = self._decap(enc, receiver_key, self._kem_id, self._hashmod, sender_key)
            else:
                shared_secret = self._decap_pq(enc, receiver_key)

        self._sequence = 0
        self._max_sequence = (1 << (8 * self._Nn)) - 1

        self._key, self._base_nonce, self._export_secret = self._key_schedule(shared_secret, info, *psk_pair)

    @staticmethod
    def _encap(
        receiver_key: EccKey,
        kem_id: int,
        hashmod: ModuleType,
        sender_key: Optional[EccKey] = None,
        eph_key: Optional[EccKey] = None,
    ) -> tuple[bytes, bytes]:
        assert (sender_key is None) or sender_key.has_private()
        assert (eph_key is None) or eph_key.has_private()

        if eph_key is None:
            eph_key = ECC.generate(curve=receiver_key.curve)
        enc = eph_key.public_key().export_key(format="raw")

        pkRm = receiver_key.public_key().export_key(format="raw")
        kem_context = enc + pkRm
        extra_param = {}
        if sender_key:
            kem_context += sender_key.public_key().export_key(format="raw")
            extra_param = {"static_priv": sender_key}

        suite_id = b"KEM" + struct.pack(">H", kem_id)

        def kdf(
            dh: bytes,
            kem_context: bytes = kem_context,
            suite_id: bytes = suite_id,
            hashmod: ModuleType = hashmod,
        ) -> bytes:
            return _extract_and_expand(dh, kem_context, suite_id, hashmod)

        shared_secret = key_agreement(eph_priv=eph_key, static_pub=receiver_key, kdf=kdf, **extra_param)
        return shared_secret, enc

    @staticmethod
    def _decap(
        enc: bytes,
        receiver_key: EccKey,
        kem_id: int,
        hashmod: ModuleType,
        sender_key: Optional[EccKey] = None,
    ) -> bytes:
        assert receiver_key.has_private()

        try:
            if receiver_key.curve == "Curve25519":
                pkE = import_x25519_public_key(enc)
            elif receiver_key.curve == "Curve448":
                pkE = import_x448_public_key(enc)
            else:
                pkE = ECC.import_key(enc, curve_name=receiver_key.curve)
        except ValueError as ve:
            raise DeserializeError("'enc' is not a valid encapsulated HPKE key") from ve

        pkRm = receiver_key.public_key().export_key(format="raw")
        kem_context = enc + pkRm
        extra_param = {}
        if sender_key:
            kem_context += sender_key.public_key().export_key(format="raw")
            extra_param = {"static_pub": sender_key}

        suite_id = b"KEM" + struct.pack(">H", kem_id)

        def kdf(
            dh: bytes,
            kem_context: bytes = kem_context,
            suite_id: bytes = suite_id,
            hashmod: ModuleType = hashmod,
        ) -> bytes:
            return _extract_and_expand(dh, kem_context, suite_id, hashmod)

        shared_secret = key_agreement(eph_pub=pkE, static_priv=receiver_key, kdf=kdf, **extra_param)
        return shared_secret

    @staticmethod
    def _encap_pq(
        receiver_key: Union[MLKEMKey, HybridKey],
        randomness: Optional[bytes] = None,
    ) -> tuple[bytes, bytes]:
        # Encap of ML-KEM and of the hybrid KEMs (draft-ietf-hpke-pq, Sections 3 and 4):
        # the shared secret of the KEM is used directly
        return receiver_key._encaps(randomness)

    @staticmethod
    def _decap_pq(enc: bytes, receiver_key: Union[MLKEMKey, HybridKey]) -> bytes:
        assert receiver_key.has_private()

        try:
            return receiver_key._decaps(enc)
        except ValueError as ve:
            raise DeserializeError("'enc' is not a valid encapsulated HPKE key") from ve

    @staticmethod
    def _verify_psk_inputs(mode: MODE, psk_pair: tuple[bytes, bytes]) -> None:
        psk_id, psk = psk_pair

        if (psk == b"") ^ (psk_id == b""):
            raise ValueError("Inconsistent PSK inputs")

        if psk == b"":
            if mode in (MODE.PSK, MODE.AUTH_PSK):
                raise ValueError(f"PSK is required with mode {mode.name}")
        else:
            if len(psk) < 32:
                raise ValueError("PSK must be at least 32 byte long")
            if mode in (MODE.BASE, MODE.AUTH):
                raise ValueError("PSK is not compatible with this mode")

    def _key_schedule(
        self, shared_secret: bytes, info: bytes, psk_id: bytes, psk: bytes
    ) -> tuple[bytes, bytes, bytes]:
        psk_id_hash = _labeled_extract(b"", b"psk_id_hash", psk_id, self._suite_id, self._hashmod)

        info_hash = _labeled_extract(b"", b"info_hash", info, self._suite_id, self._hashmod)

        key_schedule_context = self._mode.to_bytes(1, "big") + psk_id_hash + info_hash

        secret = _labeled_extract(shared_secret, b"secret", psk, self._suite_id, self._hashmod)

        if self._aead_id == AEAD.EXPORT_ONLY:
            # There is no AEAD key nor nonce
            key = base_nonce = b""
        else:
            key = _labeled_expand(
                secret, b"key", key_schedule_context, self._Nk, self._suite_id, self._hashmod
            )

            base_nonce = _labeled_expand(
                secret, b"base_nonce", key_schedule_context, self._Nn, self._suite_id, self._hashmod
            )

        exporter_secret = _labeled_expand(
            secret, b"exp", key_schedule_context, self._Nh, self._suite_id, self._hashmod
        )

        return key, base_nonce, exporter_secret

    def _new_cipher(self) -> Union[GcmMode, ChaCha20Poly1305Cipher]:
        nonce = strxor(self._base_nonce, self._sequence.to_bytes(self._Nn, "big"))
        cipher: Union[GcmMode, ChaCha20Poly1305Cipher]
        if self._aead_id in (AEAD.AES128_GCM, AEAD.AES256_GCM):
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=self._Nt)
        elif self._aead_id == AEAD.CHACHA20_POLY1305:
            cipher = ChaCha20_Poly1305.new(key=self._key, nonce=nonce)
        else:
            raise ValueError(f"Unknown AEAD cipher ID {self._aead_id:#x}")
        if self._sequence >= self._max_sequence:
            raise MessageLimitReachedError()
        self._sequence += 1
        return cipher

    def seal(self, plaintext: bytes, auth_data: Optional[bytes] = None) -> bytes:
        """Encrypt and authenticate a message.

        This method can be invoked multiple times
        to seal an ordered sequence of messages.

        Args:
          plaintext:
            The message to seal.
          auth_data:
            Optional. Additional authenticated data (AAD) that is not encrypted,
            but is also covered by the authentication tag.

        Returns:
           The ciphertext concatenated with the authentication tag.
        """

        if self._aead_id == AEAD.EXPORT_ONLY:
            raise ValueError("This is an export-only HPKE context")
        if not self._encrypt:
            raise ValueError("This cipher can only be used to seal")
        cipher = self._new_cipher()
        if auth_data:
            cipher.update(auth_data)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct + tag

    def unseal(self, ciphertext: bytes, auth_data: Optional[bytes] = None) -> bytes:
        """Decrypt a message and validate its authenticity.

        This method can be invoked multiple times
        to unseal an ordered sequence of messages.

        Args:
          ciphertext:
            The message to unseal.
          auth_data:
            Optional. Additional authenticated data (AAD) that
            was also covered by the authentication tag.

        Returns:
           The original plaintext.

        Raises:
          ValueError: if the ciphertext (in combination with the AAD) is not valid.
            At the first call of ``unseal()``, it can also mean that one of the
            keys or parameters used to set up the context is wrong or missing.
        """

        if self._aead_id == AEAD.EXPORT_ONLY:
            raise ValueError("This is an export-only HPKE context")
        if self._encrypt:
            raise ValueError("This cipher can only be used to unseal")
        if len(ciphertext) < self._Nt:
            raise ValueError("Ciphertext is too small")
        cipher = self._new_cipher()
        if auth_data:
            cipher.update(auth_data)

        try:
            pt = cipher.decrypt_and_verify(ciphertext[: -self._Nt], ciphertext[-self._Nt :])
        except ValueError:
            if self._sequence == 1:
                raise ValueError("Incorrect HPKE keys/parameters or invalid message (wrong MAC tag)")
            raise ValueError("Invalid message (wrong MAC tag)")
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        """Export a secret from this HPKE context.

        This method can be invoked multiple times,
        with different contexts, to derive independent secrets.

        Args:
          exporter_context:
            Context for the exported secret (it can be empty).
          length:
            The desired length of the secret, in bytes.
            It must not be larger than 255 times the digest size
            of the hash of the KDF (e.g., 8160 bytes for ``NIST P-256``).

        Returns:
           The exported secret.

        .. warning::
            Unlike ``unseal()``, this method never detects if sender and
            receiver used different keys or parameters: it simply returns
            a different secret. If needed, the application must
            confirm that both parties derived the same secret.
        """

        if length < 0 or length > 255 * self._Nh:
            raise ValueError("Incorrect length for exported secret")

        return _labeled_expand(
            self._export_secret, b"sec", exporter_context, length, self._suite_id, self._hashmod
        )


def new(
    *,
    receiver_key: KemKey,
    aead_id: AEAD,
    enc: Optional[bytes] = None,
    sender_key: Optional[EccKey] = None,
    psk: Optional[tuple[bytes, bytes]] = None,
    info: Optional[bytes] = None,
) -> HPKE_Cipher:
    """Create an HPKE context which can be used:

    - by the sender to seal (encrypt) a message,
    - by the receiver to unseal (decrypt) it, or
    - by either party to export shared secret material.

    As a minimum, the two parties agree on the receiver's asymmetric key
    (of which the sender will only know the public half).

    Additionally, for authentication purposes, they may also agree on:

    * the sender's asymmetric key (of which the receiver will only know the public half)

    * a shared secret (e.g., a symmetric key derived from a password)

    Args:
      receiver_key:
        The key of the receiver, which determines the KEM. One of:

        * an ECC key (:class:`Crypto.PublicKey.ECC.EccKey`), for DHKEM,
          on one of the following curves: ``NIST P-256``,
          ``NIST P-384``, ``NIST P-521``, ``X25519`` or ``X448``;
        * an ML-KEM key (:class:`Crypto.PublicKey.MLKEM.MLKEMKey`),
          of any parameter set (*post-quantum*);
        * a hybrid key (:class:`Crypto.PublicKey.Hybrid.HybridKey`)
          of the hybrid KEM X-Wing, which combines ML-KEM and X25519
          (*post-quantum/traditional hybrid*).

        If this is a **public** key, the HPKE context can only be used to
        **seal** (**encrypt**) or **export** a secret.

        If this is a **private** key, the HPKE context can only be used to
        **unseal** (**decrypt**) or **export** a secret.

      aead_id:
        The HPKE identifier of the symmetric cipher.
        The possible values are:

        * ``HPKE.AEAD.AES128_GCM``
        * ``HPKE.AEAD.AES256_GCM``
        * ``HPKE.AEAD.CHACHA20_POLY1305``
        * ``HPKE.AEAD.EXPORT_ONLY``

      enc:
        The encapsulated key (the KEM ciphertext) that the sender delivered,
        available to the sender as :attr:`HPKE_Cipher.enc`.

        The receiver must always specify this parameter.

        The sender must always omit this parameter.

      sender_key:
        The ECC key of the sender.
        It must be on the same curve as the ``receiver_key``.
        If the ``receiver_key`` is a public key, ``sender_key`` must be a
        private key, and vice versa.
        It cannot be used with ML-KEM or hybrid keys
        (they have no authenticated mode).

      psk:
        A Pre-Shared Key (PSK) as a 2-tuple of non-empty
        byte strings: the identifier and the actual secret value.
        Sender and receiver must use the same PSK (or none).

        The secret value must be at least 32 bytes long,
        but it must not be a low-entropy password
        (use a KDF like PBKDF2 or scrypt to derive a secret
        from a password).

      info:
        A non-secret parameter that contributes
        to the generation of all session keys.
        Sender and receiver must use the same **info** parameter (or none).

    Returns:
        An object that can be used for
        sealing (if ``receiver_key`` is a public key) or
        unsealing (if ``receiver_key`` is a private key),
        and in both cases for exporting secrets
        (with ``HPKE.AEAD.EXPORT_ONLY``, only for that).
        For the receiver,
        correctness of all the keys and parameters will only
        be assessed with the first call to ``unseal()``,
        and never by ``export()``.
    """

    try:
        aead_id = AEAD(aead_id)
    except ValueError as ve:
        raise ValueError(f"Unknown AEAD cipher ID {aead_id:#x}") from ve

    if isinstance(receiver_key, EccKey):
        curve = receiver_key.curve
        if curve not in ("NIST P-256", "NIST P-384", "NIST P-521", "Curve25519", "Curve448"):
            raise ValueError(f"Unsupported curve {curve}")
    elif not isinstance(receiver_key, (MLKEMKey, HybridKey)):
        raise TypeError("The receiver key must be an ECC, ML-KEM or hybrid key")

    if sender_key:
        if not isinstance(receiver_key, EccKey):
            raise ValueError("The authenticated modes of HPKE require ECC keys")
        if not isinstance(sender_key, EccKey):
            raise TypeError("The sender key must be an ECC key")
        count_private_keys = int(receiver_key.has_private()) + int(sender_key.has_private())
        if count_private_keys != 1:
            raise ValueError("Exactly 1 private key required")
        if sender_key.curve != curve:
            raise ValueError(f"Sender key uses {sender_key.curve} but recipient key {curve}")
        mode = MODE.AUTH if psk is None else MODE.AUTH_PSK
    else:
        mode = MODE.BASE if psk is None else MODE.PSK

    if psk is None:
        psk = b"", b""

    if info is None:
        info = b""

    return HPKE_Cipher(receiver_key, enc, sender_key, psk, info, aead_id, mode)
