from __future__ import annotations

from typing import Union

__all__ = [
    "Cipher",
    "Hash",
    "Protocol",
    "PublicKey",
    "Util",
    "Signature",
    "IO",
    "Math",
    "PassphraseRequiredError",
    "IncorrectPassphraseError",
    "MessageTooLongError",
    "KdfLimitError",
    "KdfIterationLimitError",
    "KdfMemoryLimitError",
]

version_info: tuple[int, int, Union[int, str]] = (4, 1, "0")

__version__: str = ".".join([str(x) for x in version_info])


class PassphraseRequiredError(ValueError):
    """The data (for instance, a private key) is encrypted,
    but no passphrase was provided.

    This is a subclass of ``ValueError``.
    """


class IncorrectPassphraseError(ValueError):
    """The encrypted data (for instance, a private key) could not be
    decrypted with the passphrase.

    Most likely, the passphrase is wrong; but the encrypted data might also
    be corrupted (the two cases cannot be told apart).

    This is a subclass of ``ValueError``.
    """


class MessageTooLongError(ValueError, OverflowError):
    """The data is longer than a cipher can process with the same key
    and nonce (for instance, the key stream would repeat).

    This is a subclass of both ``ValueError`` and ``OverflowError``.
    """


class KdfLimitError(ValueError):
    """Deriving a key from a password or a passphrase would take more time
    or memory than allowed, as set to protect against malicious data
    (for instance, an encrypted private key or a password hash that
    states an extremely high cost).

    This is a subclass of ``ValueError``.
    """


class KdfIterationLimitError(KdfLimitError):
    """The cost of the key derivation (the iteration count of PBKDF2,
    the cost of scrypt, or the rounds of bcrypt) is above the limit
    (for instance, the one set with ``max_iteration_count``).
    """


class KdfMemoryLimitError(KdfLimitError):
    """The key derivation needs more memory than the limit
    (for instance, the one set with ``max_memory``).
    """


_PASSPHRASE_REQUIRED = "The private key is encrypted: a passphrase is required"
_INCORRECT_PASSPHRASE = "Incorrect passphrase (or the encrypted private key is corrupted)"
