.. _exceptions:

Exceptions
==========

Most errors in PyCryptodome are reported with the standard Python exceptions:

* ``ValueError``, when a value is not acceptable: for instance, a key of the wrong length,
  data that cannot be parsed, or a message whose MAC tag does not match
  (for example, in :meth:`decrypt_and_verify` or in the :meth:`verify` method of a signature scheme);
* ``TypeError``, when a parameter has the wrong type: for instance, a text string instead of ``bytes``.

In a few cases, a dedicated exception tells **why** the operation failed,
so that an application can react without parsing the error message.
They are all subclasses of ``ValueError``: code that catches ``ValueError`` catches them too.
The most general ones are in the top-level package :mod:`Crypto`
(for instance, ``from Crypto import MessageTooLongError``).

.. csv-table::
    :header: Exception, Raised when
    :widths: 40, 60

    :class:`~Crypto.PassphraseRequiredError`, "An encrypted private key is imported without a passphrase."
    :class:`~Crypto.IncorrectPassphraseError`, "An encrypted private key cannot be decrypted with the passphrase."
    :class:`~Crypto.IO.PKCS8.PbesLimitError`, "Decrypting a private key would take too much time or memory."
    :exc:`~Crypto.PublicKey.ECC.UnsupportedEccFeature`, "An ECC key uses a curve or a feature that is not supported."
    :class:`~Crypto.MessageTooLongError`, "A cipher would process more data than allowed with the same key and nonce."
    :exc:`~Crypto.Protocol.HPKE.DeserializeError`, "The encapsulated key received with HPKE is not valid."
    :exc:`~Crypto.Protocol.HPKE.MessageLimitReachedError`, "An HPKE context has protected the maximum number of messages."

Importing private keys
----------------------

These exceptions are raised by:

* :func:`Crypto.PublicKey.RSA.import_key`
* :func:`Crypto.PublicKey.DSA.import_key`
* :func:`Crypto.PublicKey.ECC.import_key`

and by the lower level functions :func:`Crypto.IO.PKCS8.unwrap` and :func:`Crypto.IO.PEM.decode`.
They concern any kind of encrypted private key: PEM (with the ``Proc-Type: 4,ENCRYPTED`` header),
`PKCS#8`_ (``EncryptedPrivateKeyInfo``, DER or PEM), and OpenSSH.

.. autoexception:: Crypto.PassphraseRequiredError

.. autoexception:: Crypto.IncorrectPassphraseError

    An incorrect passphrase cannot be told apart from a corrupted encrypted key: both mean that decryption failed.

    An incorrect passphrase is detected with overwhelming probability, but not always with certainty,
    because some formats have no integrity check: with a wrong passphrase, they yield random data,
    which is recognised as such because it is not a well-formed key.
    An OpenSSH key misses an incorrect passphrase once in 2\ :sup:`32` times,
    while a `PKCS#8`_ key encrypted with GCM never does.
    In the very rare cases it is missed, a plain ``ValueError`` is raised instead.

    For instance::

        >>> from Crypto import PassphraseRequiredError, IncorrectPassphraseError
        >>> from Crypto.PublicKey import RSA
        >>>
        >>> try:
        >>>     key = RSA.import_key(data, passphrase)
        >>> except PassphraseRequiredError:
        >>>     print("This key is encrypted: please enter the passphrase")
        >>> except IncorrectPassphraseError:
        >>>     print("Wrong passphrase")
        >>> except ValueError:
        >>>     print("This is not an RSA key")

:class:`Crypto.IO.PKCS8.PbesLimitError`

    The derivation of the decryption key from the passphrase would need more time or memory
    than the limits set with the ``max_iteration_count`` and ``max_memory`` parameters
    (or than the default limits): a malicious key could otherwise tie up the CPU or all the memory.
    It is raised before the passphrase is checked.

    Its subclasses tell which limit applies:
    :class:`~Crypto.IO.PKCS8.PbesIterationCountError` (time)
    and :class:`~Crypto.IO.PKCS8.PbesMemoryError` (memory).
    See :ref:`pkcs8_limits`.

.. py:exception:: Crypto.PublicKey.ECC.UnsupportedEccFeature
    :no-index:

    The key is well-formed, but uses an elliptic curve or a key type that PyCryptodome
    does not support (an unknown curve or algorithm OID, or an unknown curve name).
    It is raised by :func:`Crypto.PublicKey.ECC.import_key` for public and private keys.

Ciphers
-------

.. autoexception:: Crypto.MessageTooLongError

    It is also an ``OverflowError``, because CTR mode and Salsa20 used to raise that.

    It is raised when a cipher cannot process more data with the same key and nonce,
    because of the size of its block counter or of its length fields,
    or because the key stream would repeat. Nothing is encrypted or decrypted then.
    For instance:

    * :ref:`CCM mode <ccm_mode>`: with a nonce of *n* bytes, the length of the message is
      encoded in 15 - *n* bytes, so the longest message is 2\ :sup:`8·(15-n)` - 1 bytes
      (64 KiB - 1 with the longest nonce of 13 bytes, 4 GiB - 1 with the default nonce of 11 bytes).
      It is raised by :func:`Crypto.Cipher.AES.new`, if the parameter ``msg_len`` is too large
      for the nonce, and by the methods ``update()``, ``encrypt()``, ``decrypt()``,
      ``encrypt_and_digest()`` and ``decrypt_and_verify()`` of the cipher object, if the data is
      longer than declared (with ``msg_len`` or ``assoc_len``) or too long for the nonce.
      It used to be called ``CCMMessageTooLongError``, which is still an alias.
    * :ref:`GCM mode <gcm_mode>`: at most 2\ :sup:`36` - 32 bytes (about 64 GiB) of data,
      and 2\ :sup:`61` - 1 bytes of associated data.
    * :ref:`CTR mode <ctr_mode>`: the counter block would wrap around to its initial value.
    * :doc:`ChaCha20 <cipher/chacha20>` and :doc:`ChaCha20-Poly1305 <cipher/chacha20_poly1305>`:
      the 32-bit block counter (with a nonce of 12 bytes, 256 GiB)
      or the 64-bit block counter (with a nonce of 8 or 24 bytes) would wrap around.
    * :doc:`Salsa20 <cipher/salsa20>`: the key stream ends after 2\ :sup:`70` bytes.
    * :ref:`KW <kw_mode>` and :ref:`KWP <kwp_mode>` modes: the plaintext must be shorter than 4 GiB.

Hybrid Public Key Encryption (HPKE)
-----------------------------------

.. py:exception:: Crypto.Protocol.HPKE.DeserializeError

    The encapsulated key ``enc`` received from the sender is not a valid public key
    for the curve of the receiver.
    It is raised by :func:`Crypto.Protocol.HPKE.new`, when creating the context of a receiver.
    See :ref:`hpke`.

.. py:exception:: Crypto.Protocol.HPKE.MessageLimitReachedError

    The context has already protected the maximum number of messages
    (2\ :sup:`96` - 1 with the AEAD ciphers of HPKE): the nonce would repeat.
    It is raised by :meth:`Crypto.Protocol.HPKE.HPKE_Cipher.seal`
    and :meth:`Crypto.Protocol.HPKE.HPKE_Cipher.unseal`.

.. _`PKCS#8`: https://datatracker.ietf.org/doc/html/rfc5208
