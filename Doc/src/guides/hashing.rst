.. _guide_hashing:

Hash data and authenticate messages
===================================

Compute a hash
--------------

A cryptographic hash (or *digest*) is a short, fixed-size fingerprint of some data:
it is practically impossible to find two different inputs with the same hash.
Use it, for instance, to check that a downloaded file is intact, or to identify content.

Use :doc:`SHA-256 <../hash/sha256>`:

.. code-block:: python

    from Crypto.Hash import SHA256

    h = SHA256.new(b"Hello")
    print(h.hexdigest())    # 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

``digest()`` returns the hash as 32 ``bytes``, ``hexdigest()`` as a hexadecimal string.

To hash a large file, or data that arrives in pieces, call ``update()`` several times:

.. code-block:: python

    h = SHA256.new()
    with open("large_file.bin", "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    print(h.hexdigest())

Other good choices are :doc:`SHA-3 <../hash/sha3_256>` (a different design, as a backup for SHA-2)
and :doc:`BLAKE2 <../hash/blake2b>` (faster in software). They have the same API.
Do not use MD5 or SHA-1 for anything related to security: they are broken.

A hash alone does not protect against an attacker who can modify the data,
because the attacker can just recompute the hash. For that, use a MAC or a signature.

.. warning::

    Do not use a hash to store passwords. See :doc:`passwords`.

Hash a massive amount of data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SHA-256 processes data sequentially, on a single CPU core.
For very large inputs (for instance, files of many gigabytes),
:doc:`KangarooTwelve <../hash/k12>` (K12) is much faster:
it is usually faster than SHA-256 even on one core, and it can hash
independent parts of the data on several cores at the same time.
Pass ``threads=0`` to use all the cores available, and read the data in large chunks
(each thread processes at least 256 KiB of a single ``update()`` call):

.. code-block:: python

    from Crypto.Hash import KangarooTwelve as K12

    h = K12.new(threads=0)
    with open("large_file.bin", "rb") as f:
        while chunk := f.read(16 * 1024 * 1024):
            h.update(chunk)
    print(h.read(32).hex())

The result does not depend on the number of threads.
K12 is an *extendable-output function*: instead of ``digest()``,
you call ``read()`` with the length of the output you need (32 bytes is a good default).

K12 (RFC 9861) is newer and less widely supported than SHA-256:
choose it when you control both the side that computes the hash and
the side that checks it.

Authenticate a message with a secret key (MAC)
----------------------------------------------

A *Message Authentication Code* (MAC) is a tag that only the holders of a secret key
can compute. The recipient recomputes the tag over the message it received,
with the same key, and compares it with the tag it received.

Use :doc:`HMAC <../hash/hmac>` with SHA-256:

.. code-block:: python

    from Crypto.Hash import HMAC
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)      # shared in advance by the two parties
    message = b"Transfer 100 EUR to Alice"

    # The sender
    tag = HMAC.new(key, message, digestmod=SHA256).digest()

    # The recipient
    try:
        HMAC.new(key, message, digestmod=SHA256).verify(tag)
        print("The message is authentic")
    except ValueError:
        print("The message or the tag were modified")

Always check a tag with ``verify()`` (or ``hexverify()``), and not with ``==``:
``verify()`` takes the same time whatever the input,
so it does not leak information about the correct tag.

.. note::

    If you also want to encrypt the message, don't add a MAC yourself:
    use authenticated encryption (see :doc:`symmetric`), which includes it.

If the recipient must be able to verify the message without being able to create
a valid tag (for instance, because there are many recipients),
use digital signatures instead (see :doc:`signatures`).

See also
--------

* :doc:`../hash/hash`, for all hash functions and MACs
  (including KMAC, CMAC, and the extendable-output functions SHAKE).
