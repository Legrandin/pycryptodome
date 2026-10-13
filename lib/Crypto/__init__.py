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
]

version_info: tuple[int, int, Union[int, str]] = (4, 0, "0b0")

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


_PASSPHRASE_REQUIRED = "The private key is encrypted: a passphrase is required"
_INCORRECT_PASSPHRASE = "Incorrect passphrase (or the encrypted private key is corrupted)"
