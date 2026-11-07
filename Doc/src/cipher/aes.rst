AES
===

.. py:currentmodule:: Crypto.Cipher.AES

AES `(Advanced Encryption Standard)`__ is a symmetric block cipher standardized
by NIST_ . It has a fixed data block size of 16 bytes.
Its keys can be 128, 192, or 256 bits long.

AES is very fast and secure, and it is the de facto standard for symmetric
encryption.

On its own, a block cipher can only encrypt a single block of 16 bytes.
To protect messages of any length, you combine it with a *mode of operation*,
which you select with the ``mode`` parameter of :func:`new`.
The table in :ref:`aes_modes` lists the modes you can choose from.

.. tip::

    For a step-by-step explanation of how to encrypt data with AES,
    including large files, see the guide :doc:`../guides/symmetric`.

For instance, you can encrypt and authenticate a message with AES in GCM mode::

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> data = b'The secret message'
    >>> key = get_random_bytes(16)
    >>> nonce = get_random_bytes(12)
    >>> cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    >>> ciphertext, tag = cipher.encrypt_and_digest(data)

You must deliver the triple ``(nonce, ciphertext, tag)`` to the recipient.
The nonce and the tag are not secret, but the key is.
With the same key, the recipient decrypts the message and checks that it is authentic::

    >>> from Crypto.Cipher import AES
    >>>
    >>> cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    >>> try:
    ...     plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    ...     print("The message is authentic:", plaintext)
    ... except ValueError:
    ...     print("Key incorrect or message corrupted")

.. __: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _NIST: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

.. _aes_modes:

Modes of operation
------------------

The object returned by :func:`new` depends on the mode of operation:
follow the link in the last column for its methods and attributes.

.. list-table::
    :header-rows: 1
    :widths: 20 30 25 25

    * - ``mode``
      - Mode of operation
      - Protects
      - Cipher object
    * - .. py:data:: MODE_GCM
            :no-typesetting:

        ``MODE_GCM``
      - :ref:`Galois/Counter Mode <gcm_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_gcm.GcmMode`
    * - .. py:data:: MODE_EAX
            :no-typesetting:

        ``MODE_EAX``
      - :ref:`EAX mode <eax_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_eax.EaxMode`
    * - .. py:data:: MODE_OCB
            :no-typesetting:

        ``MODE_OCB``
      - :ref:`Offset CodeBook <ocb_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_ocb.OcbMode`
    * - .. py:data:: MODE_SIV
            :no-typesetting:

        ``MODE_SIV``
      - :ref:`Synthetic Initialization Vector <siv_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_siv.SivMode`
    * - .. py:data:: MODE_GCM_SIV
            :no-typesetting:

        ``MODE_GCM_SIV``
      - :ref:`AES-GCM-SIV <gcm_siv_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_gcm_siv.GcmSivMode`
    * - .. py:data:: MODE_CCM
            :no-typesetting:

        ``MODE_CCM``
      - :ref:`Counter with CBC-MAC <ccm_mode>`
      - confidentiality + authenticity
      - :class:`~Crypto.Cipher._mode_ccm.CcmMode`
    * - .. py:data:: MODE_CTR
            :no-typesetting:

        ``MODE_CTR``
      - :ref:`Counter mode <ctr_mode>`
      - confidentiality only
      - :class:`~Crypto.Cipher._mode_ctr.CtrMode`
    * - .. py:data:: MODE_CBC
            :no-typesetting:

        ``MODE_CBC``
      - :ref:`Cipher-Block Chaining <cbc_mode>`
      - confidentiality only
      - :class:`~Crypto.Cipher._mode_cbc.CbcMode`
    * - .. py:data:: MODE_CFB
            :no-typesetting:

        ``MODE_CFB``
      - :ref:`Cipher FeedBack <cfb_mode>`
      - confidentiality only
      - :class:`~Crypto.Cipher._mode_cfb.CfbMode`
    * - .. py:data:: MODE_OFB
            :no-typesetting:

        ``MODE_OFB``
      - :ref:`Output FeedBack <ofb_mode>`
      - confidentiality only
      - :class:`~Crypto.Cipher._mode_ofb.OfbMode`
    * - .. py:data:: MODE_OPENPGP
            :no-typesetting:

        ``MODE_OPENPGP``
      - :ref:`OpenPGP mode <openpgp_mode>`
      - confidentiality only
      - :class:`~Crypto.Cipher._mode_openpgp.OpenPgpMode`
    * - .. py:data:: MODE_ECB
            :no-typesetting:

        ``MODE_ECB``
      - :ref:`Electronic CodeBook <ecb_mode>`
      - confidentiality only (weak)
      - :class:`~Crypto.Cipher._mode_ecb.EcbMode`
    * - .. py:data:: MODE_XTS
            :no-typesetting:

        ``MODE_XTS``
      - :ref:`XEX with ciphertext stealing <xts_mode>`
      - confidentiality only, for storage
      - :class:`~Crypto.Cipher._mode_xts.XtsMode`
    * - .. py:data:: MODE_KW
            :no-typesetting:

        ``MODE_KW``
      - :ref:`Key Wrap <kw_mode>`
      - keys (confidentiality + authenticity)
      - :class:`~Crypto.Cipher._mode_kw.KWMode`
    * - .. py:data:: MODE_KWP
            :no-typesetting:

        ``MODE_KWP``
      - :ref:`Key Wrap with Padding <kwp_mode>`
      - keys (confidentiality + authenticity)
      - :class:`~Crypto.Cipher._mode_kwp.KWPMode`

Which mode should I use?
~~~~~~~~~~~~~~~~~~~~~~~~

* If in doubt, use **GCM**, with a random 12-byte nonce.
  It is an *authenticated* mode (AEAD):
  the recipient detects if the message was modified or encrypted with a different key.
  It is also the most widely supported by other libraries.
  The other authenticated modes (EAX, OCB, CCM) are equally secure.
* Use **GCM-SIV** if you cannot guarantee that a nonce is never reused with the same key
  (or **SIV**, if you need a nonce of another size, or none at all).
* Use the *confidentiality only* modes, like CTR or CBC, only to interoperate with existing
  protocols, and then combine them with a MAC (like :mod:`Crypto.Hash.HMAC`).
  Never use ECB to encrypt more than one block.
* Use **KW** or **KWP** only to wrap other cryptographic keys.

Using the cipher object
-----------------------

* :meth:`encrypt` and :meth:`decrypt` process data.
  You can call them several times, each with the next piece of the message.
* The authenticated modes also have :meth:`update` (for associated data, that is,
  data that is authenticated but not encrypted, like a header),
  :meth:`digest` and :meth:`verify` (to create and check the MAC tag),
  and :meth:`encrypt_and_digest` and :meth:`decrypt_and_verify` (to do everything in one call).
  See the :ref:`introduction to modern modes <modern_cipher_modes>`.
* KW and KWP only have :meth:`seal` and :meth:`unseal`.
* The object also holds the parameters you must deliver to the recipient,
  such as :attr:`nonce` or :attr:`iv`, which :func:`new` generates if you don't pass them.

A cipher object is *stateful* and it can only process one message,
either for encryption or for decryption.
Create a new object (with a new nonce or IV) for each message.

API
---

.. automodule:: Crypto.Cipher.AES
   :members:
   :exclude-members: MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR, MODE_OPENPGP, MODE_CCM, MODE_EAX, MODE_SIV, MODE_GCM, MODE_OCB, MODE_KW, MODE_KWP, MODE_GCM_SIV, MODE_XTS
   :member-order: bysource
